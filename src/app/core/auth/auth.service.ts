import { Injectable, computed, signal, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';

import { environment } from '../../../environments/environment';
import { generateCodeChallenge, generateRandomString } from './pkce.util';

interface TokenResponse {
  access_token: string;
  id_token?: string;
  token_type: string;
  expires_in: number;
}

interface StoredToken {
  accessToken: string;
  idToken: string | null;
  expiresAt: number;
}

/** Claims custom do access token (ver JwtClaimsCustomizer no NimbusCoreServer) - groups/
 *  permissions já vêm filtrados pelo appKey do client atual ("nimbuscore"), então decodificar
 *  client-side aqui é seguro pra exibição (ex.: tela de Perfil) sem round-trip nenhum; nunca usado
 *  como fonte de verdade de autorização (o backend valida tudo de novo via CheckSecurity). */
export interface TokenClaims {
  userId: string | null;
  username: string | null;
  name: string | null;
  groups: string[];
  permissions: string[];
}

const STORAGE_KEY = 'nimbuscore_web_token';
const PENDING_KEY = 'nimbuscore_web_oauth_pending';

/** Quanto tempo uma tentativa de login pendente fica válida pra ser resgatada no callback -
 *  generoso o bastante pro usuário digitar credenciais/MFA na tela do NimbusCore. */
const PENDING_TTL_MS = 10 * 60 * 1000;
/** Trava o crescimento do sessionStorage em cenários com muitas tentativas descartadas em
 *  sequência (ver PendingLogin). */
const MAX_PENDING = 5;

interface PendingLogin {
  state: string;
  verifier: string;
  returnTo: string;
  createdAt: number;
}

/**
 * Authorization Code + PKCE direto contra o NimbusCore (client público "nimbuscore-web", sem
 * client-secret e sem grant de refresh_token - ver RegisteredClientBootstrap/AuthServerProperties.
 * Access token de vida curta (10min, mesmo TTL dos outros clients) guardado em sessionStorage;
 * quando expira, ensureAuthenticated() manda o usuário de volta pro /oauth2/authorize - como a
 * sessão de login do NimbusCore (cookie, ver SecurityConfig#webChain) costuma continuar válida,
 * isso normalmente é transparente (sem pedir senha de novo), sem precisar de silent-renew via
 * iframe (mais simples e sem os problemas de cookie de terceiros de invisible iframe).
 */
@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly http = inject(HttpClient);

  private readonly tokenState = signal<StoredToken | null>(this.readStoredToken());

  readonly isAuthenticated = computed(() => {
    const token = this.tokenState();
    return !!token && token.expiresAt > Date.now();
  });

  /** Timestamp (ms) de expiração do access token atual, ou null se não autenticado - usado pelo
   *  SessionService pro contador de tempo de sessão no header. */
  readonly expiresAt = computed(() => this.tokenState()?.expiresAt ?? null);

  /** Username (claim "username", ver JwtClaimsCustomizer) do usuário logado, lido direto do
   *  payload do access token - decode client-side só pra UI (ex.: bloquear auto-desativação na
   *  tela de Usuários), NUNCA usado como fonte de verdade de segurança (o backend valida tudo de
   *  novo via CheckSecurity). */
  readonly currentUsername = computed(() =>
    this.decodeUsername(this.tokenState()?.accessToken ?? null),
  );

  /** Claims completos do access token atual (ver TokenClaims) - alimenta MeStore. */
  readonly claims = computed<TokenClaims | null>(() =>
    this.decodeClaims(this.tokenState()?.accessToken ?? null),
  );

  get accessToken(): string | null {
    const token = this.tokenState();
    if (!token || token.expiresAt <= Date.now()) {
      return null;
    }
    return token.accessToken;
  }

  /** Reduz o disparo redundante quando várias chamadas 401 concorrentes (ver authInterceptor)
   *  acionam startLogin() ao mesmo tempo - evita gerar vários code challenges/gravações à toa.
   *  Setada SINCRONAMENTE, antes de qualquer await, pra fechar a janela de corrida dentro desta
   *  mesma instância. NÃO é mais a única defesa contra tentativas concorrentes (ver PendingLogin
   *  abaixo) - sozinha não cobre startLogin() disparado por um DOCUMENTO JS diferente, como o
   *  prerendering especulativo do Chrome ao digitar/colar a URL raiz na barra de endereço (o
   *  Chrome carrega a página em 2º plano numa instância JS separada antes de você confirmar; como
   *  o login é uma navegação cross-origin, ele aborta e reinicia, mas o sessionStorage escrito
   *  pela tentativa fantasma sobrevive e conflitava com o par da tentativa real). */
  private loginRedirectInFlight = false;

  /** Redireciona (navegação de página inteira, não XHR) pro /oauth2/authorize do NimbusCore.
   *  Cada chamada empilha uma NOVA tentativa pendente em vez de sobrescrever a anterior (ver
   *  PendingLogin) - assim, mesmo que múltiplas tentativas concorrentes cheguem a gravar no
   *  sessionStorage (prerender do Chrome, HMR do dev-server, abas duplicadas, 401 concorrentes),
   *  o callback consegue resgatar a que efetivamente completou o round-trip, não só a última. */
  async startLogin(returnTo: string): Promise<void> {
    if (this.loginRedirectInFlight) {
      return;
    }
    this.loginRedirectInFlight = true;

    try {
      const verifier = generateRandomString();
      const state = generateRandomString(32);
      const challenge = await generateCodeChallenge(verifier);

      const pending = this.readPending();
      pending.push({ state, verifier, returnTo: returnTo || '/', createdAt: Date.now() });
      this.writePending(pending.slice(-MAX_PENDING));

      const url = new URL('/oauth2/authorize', environment.auth.issuer);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('client_id', environment.auth.clientId);
      url.searchParams.set('scope', environment.auth.scope);
      url.searchParams.set('redirect_uri', environment.auth.redirectUri);
      url.searchParams.set('state', state);
      url.searchParams.set('code_challenge', challenge);
      url.searchParams.set('code_challenge_method', 'S256');

      window.location.assign(url.toString());
    } catch (err) {
      // Falha antes de sair da página (ex.: Web Crypto indisponível) - libera a trava, senão um
      // retry do usuário ficaria travado pra sempre nesta mesma carga de página.
      this.loginRedirectInFlight = false;
      throw err;
    }
  }

  /** Chamado pela rota /auth-callback - troca o code pelo token e devolve a rota pra onde voltar.
   *  Busca a tentativa pendente pelo "state" (não assume que é a única/mais recente - ver
   *  startLogin) e descarta só ela, preservando outras tentativas concorrentes ainda em voo. */
  async handleCallback(code: string, state: string): Promise<string> {
    const pending = this.readPending();
    const index = pending.findIndex((p) => p.state === state);

    if (index === -1) {
      throw new Error('Estado OAuth2 inválido ou expirado - tente entrar novamente.');
    }

    const [match] = pending.splice(index, 1);
    this.writePending(pending);

    const body = new HttpParams()
      .set('grant_type', 'authorization_code')
      .set('code', code)
      .set('redirect_uri', environment.auth.redirectUri)
      .set('client_id', environment.auth.clientId)
      .set('code_verifier', match.verifier);

    const response = await firstValueFrom(
      this.http.post<TokenResponse>(
        new URL('/oauth2/token', environment.auth.issuer).toString(),
        body.toString(),
        {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        },
      ),
    );

    this.storeToken(response);

    return match.returnTo;
  }

  /** Lê as tentativas de login pendentes, descartando as expiradas (ver PENDING_TTL_MS). */
  private readPending(): PendingLogin[] {
    try {
      const raw = sessionStorage.getItem(PENDING_KEY);
      if (!raw) return [];
      const list = JSON.parse(raw) as PendingLogin[];
      const now = Date.now();
      return list.filter((p) => now - p.createdAt < PENDING_TTL_MS);
    } catch {
      return [];
    }
  }

  private writePending(list: PendingLogin[]): void {
    if (list.length === 0) {
      sessionStorage.removeItem(PENDING_KEY);
    } else {
      sessionStorage.setItem(PENDING_KEY, JSON.stringify(list));
    }
  }

  /** RP-Initiated Logout (OIDC) - encerra a sessão/SSO do NimbusCore, não só o token local. */
  logout(): void {
    const token = this.tokenState();
    this.clearToken();

    const url = new URL('/connect/logout', environment.auth.issuer);
    if (token?.idToken) {
      url.searchParams.set('id_token_hint', token.idToken);
    }
    url.searchParams.set('post_logout_redirect_uri', environment.auth.postLogoutRedirectUri);
    window.location.assign(url.toString());
  }

  private storeToken(response: TokenResponse): void {
    const stored: StoredToken = {
      accessToken: response.access_token,
      idToken: response.id_token ?? null,
      // -5s de margem de segurança contra relógio/latência de rede.
      expiresAt: Date.now() + Math.max(0, response.expires_in - 5) * 1000,
    };
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(stored));
    this.tokenState.set(stored);
  }

  private clearToken(): void {
    sessionStorage.removeItem(STORAGE_KEY);
    this.tokenState.set(null);
  }

  private decodeUsername(accessToken: string | null): string | null {
    if (!accessToken) return null;
    try {
      const payload = accessToken.split('.')[1];
      const base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
      const json = JSON.parse(atob(base64)) as { username?: unknown };
      return typeof json.username === 'string' ? json.username : null;
    } catch {
      return null;
    }
  }

  private decodeClaims(accessToken: string | null): TokenClaims | null {
    if (!accessToken) return null;
    try {
      const payload = accessToken.split('.')[1];
      const base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
      const json = JSON.parse(atob(base64)) as {
        userId?: unknown;
        username?: unknown;
        name?: unknown;
        groups?: unknown;
        permissions?: unknown;
      };

      return {
        userId: typeof json.userId === 'string' ? json.userId : null,
        username: typeof json.username === 'string' ? json.username : null,
        name: typeof json.name === 'string' ? json.name : null,
        groups: Array.isArray(json.groups) ? json.groups.filter((g): g is string => typeof g === 'string') : [],
        permissions: Array.isArray(json.permissions)
          ? json.permissions.filter((p): p is string => typeof p === 'string')
          : [],
      };
    } catch {
      return null;
    }
  }

  private readStoredToken(): StoredToken | null {
    try {
      const raw = sessionStorage.getItem(STORAGE_KEY);
      if (!raw) return null;
      return JSON.parse(raw) as StoredToken;
    } catch {
      return null;
    }
  }
}
