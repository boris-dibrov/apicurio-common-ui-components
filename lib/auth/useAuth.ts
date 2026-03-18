import { User, UserManager } from "oidc-client-ts";
import { AuthConfig, AuthConfigContext } from "./AuthConfigContext.ts";
import { useContext } from "react";


/** ********************************
 * OIDC auth implementation
 ** ******************************** */

const OIDC_CONFIG_OPTIONS: string[] = ["url", "clientId", "redirectUri", "scope", "logoutUrl", "loadUserInfo", "useStateBasedRedirect", "stateMaxAge", "onRedirect"];
const OIDC_DEFAULT_SCOPES = "openid profile email";
const SESSION_STORAGE_PREFIX = "apicurio.oidc.state.";
const OIDC_CALLBACK_PARAM_NAMES = ["state", "code", "error", "error_description", "error_uri", "session_state", "iss"];
const DEFAULT_STATE_MAX_AGE = 300000; // 5 minutes

function only(items: string[], allOptions: any): any {
    const rval: any = {};
    items.forEach(item => {
        if (allOptions[item] !== undefined) {
            rval[item] = allOptions[item];
        }
    });
    return rval;
}

/** ********************************
 * Session storage helpers for state-based redirection
 ** ******************************** */

interface StoredRedirectState {
    location: string;
    timestamp: number;
}

/**
 * Generate a unique state ID for storing redirect location
 */
function generateStateId(): string {
    // Use crypto.randomUUID() if available, otherwise fallback to timestamp + random
    if (typeof crypto !== "undefined" && crypto.randomUUID) {
        return crypto.randomUUID();
    }
    return `${Date.now()}-${Math.random().toString(36).substring(2, 15)}`;
}

/**
 * Store the redirect location in session storage
 */
function storeRedirectLocation(stateId: string, location: string): void {
    const key = `${SESSION_STORAGE_PREFIX}${stateId}`;
    const state: StoredRedirectState = {
        location,
        timestamp: Date.now()
    };
    sessionStorage.setItem(key, JSON.stringify(state));
}

/**
 * Retrieve the redirect location from session storage
 */
function getRedirectLocation(stateId: string): string | null {
    const key = `${SESSION_STORAGE_PREFIX}${stateId}`;
    const stored = sessionStorage.getItem(key);
    if (!stored) {
        return null;
    }
    try {
        const state: StoredRedirectState = JSON.parse(stored);
        return state.location;
    } catch (e) {
        console.error("[Auth] Error parsing stored redirect state:", e);
        return null;
    }
}

/**
 * Clear a specific redirect location from session storage
 */
function clearRedirectLocation(stateId: string): void {
    const key = `${SESSION_STORAGE_PREFIX}${stateId}`;
    sessionStorage.removeItem(key);
}

function clearAllRedirectLocations(): void {
    const keysToRemove: string[] = [];

    for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        if (key && key.startsWith(SESSION_STORAGE_PREFIX)) {
            keysToRemove.push(key);
        }
    }

    keysToRemove.forEach(key => sessionStorage.removeItem(key));
}

/**
 * Clean up expired state entries from session storage
 */
function cleanupExpiredStates(maxAge: number): void {
    const now = Date.now();
    const keysToRemove: string[] = [];

    // Iterate through all session storage keys
    for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        if (key && key.startsWith(SESSION_STORAGE_PREFIX)) {
            const stored = sessionStorage.getItem(key);
            if (stored) {
                try {
                    const state: StoredRedirectState = JSON.parse(stored);
                    if (now - state.timestamp > maxAge) {
                        keysToRemove.push(key);
                    }
                } catch {
                    // If we can't parse it, remove it
                    keysToRemove.push(key);
                }
            }
        }
    }

    // Remove expired entries
    keysToRemove.forEach(key => sessionStorage.removeItem(key));

    if (keysToRemove.length > 0) {
        console.debug(`[Auth] Cleaned up ${keysToRemove.length} expired state entries`);
    }
}

/**
 * Validate that a redirect location is safe to navigate to
 */
function isValidRedirectLocation(location: string): boolean {
    if (!location || location.trim() === "") {
        return false;
    }

    // Only allow relative paths (must start with "/" and not contain "://")
    if (!location.startsWith("/") || location.includes("://")) {
        console.warn(`[Auth] Invalid redirect location (must be relative path): ${location}`);
        return false;
    }

    // Basic XSS prevention - reject javascript: protocol
    if (location.toLowerCase().startsWith("javascript:")) {
        console.warn(`[Auth] Blocked potentially malicious redirect location: ${location}`);
        return false;
    }

    return true;
}

function isOidcCallbackUrl(url: URL): boolean {
    // Only treat the URL as a callback when the provider actually returned OIDC callback params.
    const params = url.searchParams;
    return params.has("state") && (params.has("code") || params.has("error"));
}

function removeOidcCallbackParams(url: URL): string {
    // Remove callback params so a regular reload is not mistaken for another callback.
    const searchParams = new URLSearchParams(url.search);

    OIDC_CALLBACK_PARAM_NAMES.forEach(param => searchParams.delete(param));

    const query = searchParams.toString();
    return `${url.pathname}${query ? `?${query}` : ""}${url.hash}`;
}

function isUserSessionValid(user: User | null | undefined): user is User {
    // A stored user is only reusable when it still has a non-expired access token.
    return !!user && !!user.access_token && user.expired !== true;
}

function getRedirectStateIdFromUserState(state: unknown): string | null {
    // The callback only carries a redirect-state id, the actual route is kept in sessionStorage.
    if (!state || typeof state !== "object") {
        return null;
    }

    return "redirectStateId" in state && typeof state.redirectStateId === "string" ? state.redirectStateId : null;
}

let userManager: UserManager | undefined = undefined;
let oidcConfigOptions: any;

const oidc_createUserManager = (options: any): UserManager => {
    oidcConfigOptions = only(OIDC_CONFIG_OPTIONS, options);

    return new UserManager({
        authority: oidcConfigOptions.url,
        client_id: oidcConfigOptions.clientId,
        redirect_uri: oidcConfigOptions.redirectUri,
        response_type: "code",
        scope: oidcConfigOptions.scope || OIDC_DEFAULT_SCOPES,
        filterProtocolClaims: true,
        includeIdTokenInSilentRenew: true,
        includeIdTokenInSilentSignout: true,
        loadUserInfo: oidcConfigOptions.loadUserInfo ?? true
    });
};

async function clearOidcAuthState(): Promise<void> {
    // Stop silent renew first so the library does not keep retrying a broken session.
    userManager?.stopSilentRenew();
    clearAllRedirectLocations();

    try {
        // Remove the stored user so the next bootstrap cannot reuse a broken session.
        await userManager?.removeUser();
    } catch (e) {
        console.error("[Auth] Error removing OIDC user from storage: ", e);
    }

    try {
        // Drop transient authorize/refresh state that could poison the next login attempt.
        await userManager?.clearStaleState();
    } catch (e) {
        console.error("[Auth] Error clearing stale OIDC state: ", e);
    }
}

async function clearOidcAuthStateAndThrow(logMessage: string, error: Error): Promise<never> {
    await clearOidcAuthState();
    console.error(logMessage, error);
    throw error;
}

function startOidcSilentRenew(): void {
    // Only enable silent renew after the session has been established successfully.
    userManager?.startSilentRenew();
    console.debug("[Auth] Started silent token renewal");
}

function redirectToLocation(location: string): void {
    // Let the host app handle SPA navigation when available and fall back to a hard redirect.
    if (oidcConfigOptions.onRedirect) {
        oidcConfigOptions.onRedirect(location);
    } else {
        window.location.href = location;
    }
}

async function oidc_beginLoginRedirect(): Promise<void> {
    console.debug("[Auth] Starting OIDC login redirect");
    const useStateBasedRedirect = oidcConfigOptions.useStateBasedRedirect !== false;
    const stateMaxAge = oidcConfigOptions.stateMaxAge || DEFAULT_STATE_MAX_AGE;

    await userManager?.clearStaleState();

    if (useStateBasedRedirect) {
        cleanupExpiredStates(stateMaxAge);

        const stateId = generateStateId();
        const currentLocation =
            window.location.pathname +
            window.location.search +
            window.location.hash;

        storeRedirectLocation(stateId, currentLocation);
        console.debug(`[Auth] Stored redirect location in session storage: ${currentLocation}`);

        return userManager?.signinRedirect({
            state: { redirectStateId: stateId }
        });
    }

    return userManager?.signinRedirect();
}

async function oidc_handleCallback(url: URL): Promise<void> {
    let user: User | null | undefined;

    try {
        console.debug("[Auth] Processing OIDC callback");

        // Parse the provider response only for a real OIDC callback URL.
        user = await userManager?.signinRedirectCallback();
    } catch (e) {
        return clearOidcAuthStateAndThrow(
            "[Auth] Error processing OIDC callback:",
            e instanceof Error ? e : new Error("[Auth] Error processing OIDC callback."),
        );
    }

    if (!user) {
        return clearOidcAuthStateAndThrow(
            "[Auth] Error processing OIDC callback:",
            new Error("OIDC callback completed without a user."),
        );
    }

    startOidcSilentRenew();

    const useStateBasedRedirect = oidcConfigOptions.useStateBasedRedirect !== false;
    if (useStateBasedRedirect && user.state) {
        const stateId = getRedirectStateIdFromUserState(user.state);
        const storedLocation = stateId ? getRedirectLocation(stateId) : null;

        if (stateId) {
            clearRedirectLocation(stateId);
        }

        if (storedLocation && isValidRedirectLocation(storedLocation)) {
            console.debug(`[Auth] Redirecting to stored location: ${storedLocation}`);
            return redirectToLocation(storedLocation);
        }

        console.debug("[Auth] No valid stored location found after OIDC callback");
    }

    // If the app stays on the callback route, remove OIDC params from the address bar.
    const cleanLocation = removeOidcCallbackParams(url);
    window.history.replaceState({}, document.title, cleanLocation);
}

const oidc_login = async (): Promise<void> => {
    console.debug("[Auth] Bootstrapping OIDC authentication");
    const url = new URL(window.location.href);

    if (isOidcCallbackUrl(url)) {
        return oidc_handleCallback(url);
    }

    const currentUser = await userManager?.getUser();

    if (!currentUser) {
        return oidc_beginLoginRedirect();
    }

    if (isUserSessionValid(currentUser)) {
        console.debug("[Auth] Reusing stored OIDC user");
        return startOidcSilentRenew();
    }

    try {
        console.debug("[Auth] Stored OIDC user is expired or invalid, attempting refresh");
        await oidc_refresh();

        startOidcSilentRenew();
    } catch (e) {
        console.warn("[Auth] OIDC refresh failed during bootstrap, starting a new login redirect", e);
        return oidc_beginLoginRedirect();
    }
};

const oidc_refresh = async (): Promise<void> => {
    try {
        console.debug("[Auth] Refreshing token using OIDC");

        const user = await userManager?.signinSilent();

        if (!isUserSessionValid(user)) {
            // Treat a refresh result without a valid user as a hard failure.
            return clearOidcAuthStateAndThrow(
                "[Auth] Error refreshing token using OIDC:",
                new Error("OIDC silent refresh returned no valid user."),
            );
        }
    } catch (e) {
        return clearOidcAuthStateAndThrow(
            "[Auth] Error refreshing token using OIDC:",
            e instanceof Error ? e : new Error("[Auth] Error refreshing token using OIDC."),
        );
    }
};

const oidc_logout = async (): Promise<void> => {
    // Capture the id_token before removing the user, as Okta and other providers expect id_token_hint
    const user: User | null | undefined = await userManager?.getUser();
    const idToken = user?.id_token;
    return userManager?.removeUser().then(() => {
        return userManager?.signoutRedirect({
            id_token_hint: idToken,
            post_logout_redirect_uri: oidcConfigOptions.logoutUrl || window.location.href
        });
    });
};

const oidc_isAuthenticated = async (): Promise<boolean> => {
    // Only expose the session as authenticated while the stored token is still usable.
    const user = await userManager?.getUser();
    return isUserSessionValid(user);
};

const oidc_getAccessToken = async (): Promise<string> => {
    const user: User | null | undefined = await userManager?.getUser();
    return Promise.resolve(user?.access_token as string);
};

const oidc_getIdToken = async (): Promise<string> => {
    const user: User | null | undefined = await userManager?.getUser();
    return Promise.resolve(user?.id_token as string);
};

const oidc_getUsername = async (): Promise<string> => {
    const user = await userManager?.getUser();
    return Promise.resolve(user?.profile.preferred_username as string);
};

/** ********************************
 * Basic auth implementation
 ** ******************************** */

let username: string | undefined = undefined;
let password: string | undefined = undefined;

const basic_login = async (usernameValue: string, passwordValue: string): Promise<void> => {
    try {
        console.debug("[Auth] Setting Username and Password for BasicAuth");
        username = usernameValue;
        password = passwordValue;
    } catch (e) {
        console.error("[Auth] Error logging in using BasicAuth: ", e);
    }
};

const basic_logout = async (): Promise<void> => {
    console.debug("[Auth] Logout for BasicAuth");
    username = undefined;
    password = undefined;
    window.location.reload();
    return;
};

const basic_isAuthenticated = async (): Promise<boolean> => {
    return username !== undefined && password !== undefined;
};

const basic_getUsername = async (): Promise<string> => {
    return Promise.resolve(username!);
};

const basic_getUsernameAndPassword = (): UsernameAndPassword | undefined => {
    if (username !== undefined && password != undefined) {
        return {
            username: username,
            password: password
        };
    } else {
        return undefined;
    }
};

/** ********************************
 * AuthService interface and hook.
 ** ******************************** */

export interface UsernameAndPassword {
  username: string;
  password: string;
}

export interface AuthService {
    isOidcAuthEnabled: () => boolean;
    isBasicAuthEnabled: () => boolean;
    isAuthenticated: () => Promise<boolean>;
    getUsername: () => Promise<string | undefined>;
    getToken: () => Promise<string | undefined>;
    getUsernameAndPassword: () => UsernameAndPassword | undefined;
    login: (username: string, password: string) => Promise<void>;
    refresh: () => Promise<void>;
    logout: () => Promise<void>;
}

/**
 * React hook to get the application Auth service.
 */
export const useAuth: () => AuthService = (): AuthService => {
    const config: AuthConfig = useContext(AuthConfigContext);

    if (config.type === "oidc") {
        // TODO: if the config changes after we've initialized the UserManager, should we detect that and relogin or something?
        if (userManager === undefined) {
            console.debug("[Auth] Creating OIDC UserManager with options: ", config.options);
            userManager = oidc_createUserManager(config.options);
        }
        return {
            isOidcAuthEnabled: () => true,
            isBasicAuthEnabled: () => false,
            isAuthenticated: oidc_isAuthenticated,
            getToken: async () => {
                if (config.options.logTokens) {
                    const user: User | null | undefined = await userManager?.getUser();
                    console.debug("[Auth] ID Token:");
                    console.debug(user?.id_token);
                    console.debug("[Auth] Access Token:");
                    console.debug(user?.access_token);
                }
                return config.options.tokenType === "id" ? oidc_getIdToken() : oidc_getAccessToken();
            },
            getUsernameAndPassword: () => undefined,
            getUsername: oidc_getUsername,
            login: oidc_login,
            refresh: oidc_refresh,
            logout: oidc_logout
        };
    } else if (config.type === "basic") {
        return {
            isOidcAuthEnabled: () => false,
            isBasicAuthEnabled: () => true,
            isAuthenticated: basic_isAuthenticated,
            getToken: async () => undefined,
            getUsernameAndPassword: basic_getUsernameAndPassword,
            getUsername: basic_getUsername,
            login: basic_login,
            refresh: () => Promise.resolve(),
            logout: basic_logout
        };
    }

    // Default: no auth
    return {
        isOidcAuthEnabled: () => false,
        isBasicAuthEnabled: () => false,
        isAuthenticated: () => Promise.resolve(false),
        getToken: () => Promise.resolve(undefined),
        getUsername: () => Promise.resolve(undefined),
        getUsernameAndPassword: () => undefined,
        login: () => Promise.resolve(),
        refresh: () => Promise.resolve(),
        logout: () => Promise.resolve()
    };
};
