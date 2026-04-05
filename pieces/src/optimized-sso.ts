/**
 * optimized-sso.ts
 *
 * This file contains optimized standalone implementations for OAuth2 SSO,
 * designed to work natively in environments like Cloudflare Workers.
 * It provides lightweight alternatives to the full better-auth social provider
 * system, allowing you to generate authorization URLs, validate codes, and
 * fetch user profiles (focusing on Google and Microsoft Entra ID).
 */

function encodeBase64(buffer: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < buffer.byteLength; i++) {
        binary += String.fromCharCode(buffer[i]);
    }
    return btoa(binary);
}

function encodeBase64Url(buffer: Uint8Array): string {
    return encodeBase64(buffer).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export interface OAuthProviderOptions {
    clientId: string;
    clientSecret?: string;
    redirectURI: string;
    authorizationEndpoint: string;
    tokenEndpoint: string;
    scopes?: string[];
}

export interface GoogleOptions extends Omit<OAuthProviderOptions, 'authorizationEndpoint' | 'tokenEndpoint'> {
    accessType?: "offline" | "online";
    prompt?: string;
}

export interface MicrosoftOptions extends Omit<OAuthProviderOptions, 'authorizationEndpoint' | 'tokenEndpoint'> {
    tenantId?: string;
    authority?: string;
    prompt?: string;
}

export async function generateCodeChallenge(codeVerifier: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(codeVerifier);
    const hash = await crypto.subtle.digest("SHA-256", data);
    return encodeBase64Url(new Uint8Array(hash));
}

export async function createOAuth2AuthorizationUrl(
    options: OAuthProviderOptions,
    state: string,
    codeVerifier?: string,
    additionalParams?: Record<string, string>
): Promise<URL> {
    const url = new URL(options.authorizationEndpoint);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", options.clientId);
    url.searchParams.set("state", state);
    url.searchParams.set("redirect_uri", options.redirectURI);

    if (options.scopes && options.scopes.length > 0) {
        url.searchParams.set("scope", options.scopes.join(" "));
    }

    if (codeVerifier) {
        const codeChallenge = await generateCodeChallenge(codeVerifier);
        url.searchParams.set("code_challenge_method", "S256");
        url.searchParams.set("code_challenge", codeChallenge);
    }

    if (additionalParams) {
        for (const [key, value] of Object.entries(additionalParams)) {
            url.searchParams.set(key, value);
        }
    }

    return url;
}

export function createGoogleAuthorizationUrl(options: GoogleOptions, state: string, codeVerifier: string): Promise<URL> {
    const scopes = options.scopes?.length ? options.scopes : ["email", "profile", "openid"];
    const params: Record<string, string> = {};
    if (options.accessType) params.accessType = options.accessType;
    if (options.prompt) params.prompt = options.prompt;
    params.include_granted_scopes = "true";

    return createOAuth2AuthorizationUrl({
        ...options,
        authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
        tokenEndpoint: "https://oauth2.googleapis.com/token",
        scopes
    }, state, codeVerifier, params);
}

export function createMicrosoftAuthorizationUrl(options: MicrosoftOptions, state: string, codeVerifier: string): Promise<URL> {
    const tenant = options.tenantId || "common";
    const authority = options.authority || "https://login.microsoftonline.com";
    const scopes = options.scopes?.length ? options.scopes : ["openid", "profile", "email", "User.Read", "offline_access"];
    const params: Record<string, string> = {};
    if (options.prompt) params.prompt = options.prompt;

    return createOAuth2AuthorizationUrl({
        ...options,
        authorizationEndpoint: `${authority}/${tenant}/oauth2/v2.0/authorize`,
        tokenEndpoint: `${authority}/${tenant}/oauth2/v2.0/token`,
        scopes
    }, state, codeVerifier, params);
}

export interface OAuth2Tokens {
    accessToken: string;
    refreshToken?: string;
    idToken?: string;
    expiresIn?: number;
    raw: Record<string, any>;
}

export async function validateOAuth2AuthorizationCode(
    options: OAuthProviderOptions,
    code: string,
    codeVerifier?: string,
    authentication?: "basic" | "post"
): Promise<OAuth2Tokens> {
    const body = new URLSearchParams();
    const headers: Record<string, string> = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    };

    body.set("grant_type", "authorization_code");
    body.set("code", code);
    body.set("redirect_uri", options.redirectURI);
    if (codeVerifier) {
        body.set("code_verifier", codeVerifier);
    }

    if (authentication === "basic" && options.clientSecret) {
        const encodedCredentials = btoa(`${options.clientId}:${options.clientSecret}`);
        headers["Authorization"] = `Basic ${encodedCredentials}`;
    } else {
        body.set("client_id", options.clientId);
        if (options.clientSecret) {
            body.set("client_secret", options.clientSecret);
        }
    }

    const response = await fetch(options.tokenEndpoint, {
        method: "POST",
        headers,
        body
    });

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to validate authorization code: ${response.status} ${errorText}`);
    }

    const data = await response.json() as Record<string, any>;

    return {
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        idToken: data.id_token,
        expiresIn: data.expires_in,
        raw: data
    };
}

export async function validateGoogleAuthorizationCode(options: GoogleOptions, code: string, codeVerifier: string): Promise<OAuth2Tokens> {
    return validateOAuth2AuthorizationCode({
        ...options,
        authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
        tokenEndpoint: "https://oauth2.googleapis.com/token",
    }, code, codeVerifier, "post");
}

export async function validateMicrosoftAuthorizationCode(options: MicrosoftOptions, code: string, codeVerifier: string): Promise<OAuth2Tokens> {
    const tenant = options.tenantId || "common";
    const authority = options.authority || "https://login.microsoftonline.com";
    return validateOAuth2AuthorizationCode({
        ...options,
        authorizationEndpoint: `${authority}/${tenant}/oauth2/v2.0/authorize`,
        tokenEndpoint: `${authority}/${tenant}/oauth2/v2.0/token`,
    }, code, codeVerifier, "post");
}

export interface UserInfo {
    id: string;
    email: string;
    name: string;
    picture?: string;
    emailVerified?: boolean;
    raw: any;
}

/**
 * Basic JWT Decoder. Does not verify signature. Use proper JWT verification library for security!
 */
export function decodeJwt(token: string): any {
    try {
        const parts = token.split(".");
        if (parts.length !== 3) throw new Error("Invalid JWT");
        const payload = parts[1];
        // base64Url decode logic
        let base64 = payload.replace(/-/g, "+").replace(/_/g, "/");
        while (base64.length % 4) base64 += "=";
        const jsonPayload = decodeURIComponent(atob(base64).split('').map((c) => {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
        return JSON.parse(jsonPayload);
    } catch (e) {
        return null;
    }
}

export async function getGoogleUserInfo(tokens: OAuth2Tokens): Promise<UserInfo> {
    if (tokens.idToken) {
        const payload = decodeJwt(tokens.idToken);
        if (payload) {
            return {
                id: payload.sub,
                email: payload.email,
                name: payload.name,
                picture: payload.picture,
                emailVerified: payload.email_verified,
                raw: payload
            };
        }
    }

    // Fallback to calling UserInfo API if ID token is missing or undecodable
    const res = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
        headers: {
            "Authorization": `Bearer ${tokens.accessToken}`
        }
    });

    if (!res.ok) {
        throw new Error(`Failed to fetch Google user info: ${res.status}`);
    }

    const data = await res.json() as any;
    return {
        id: data.sub,
        email: data.email,
        name: data.name,
        picture: data.picture,
        emailVerified: data.email_verified,
        raw: data
    };
}

export async function getMicrosoftUserInfo(tokens: OAuth2Tokens, profilePhotoSize: number = 48): Promise<UserInfo> {
    if (!tokens.idToken) {
        throw new Error("Microsoft Entra ID requires an idToken to extract user profile.");
    }

    const payload = decodeJwt(tokens.idToken);
    if (!payload) {
        throw new Error("Invalid Microsoft ID token.");
    }

    const email = payload.email || payload.preferred_username;
    let pictureUrl = undefined;

    try {
        // Attempt to fetch profile picture
        const res = await fetch(`https://graph.microsoft.com/v1.0/me/photos/${profilePhotoSize}x${profilePhotoSize}/$value`, {
            headers: {
                "Authorization": `Bearer ${tokens.accessToken}`
            }
        });

        if (res.ok) {
            const buffer = await res.arrayBuffer();
            const base64Pic = encodeBase64(new Uint8Array(buffer));
            pictureUrl = `data:image/jpeg;base64, ${base64Pic}`;
        }
    } catch (e) {
        // Ignore picture fetch errors
    }

    const emailVerified = payload.email_verified !== undefined
        ? payload.email_verified
        : (payload.email && (payload.verified_primary_email?.includes(payload.email) || payload.verified_secondary_email?.includes(payload.email)) ? true : false);

    return {
        id: payload.sub || payload.oid,
        email: email,
        name: payload.name || `${payload.given_name || ''} ${payload.family_name || ''}`.trim(),
        picture: pictureUrl,
        emailVerified: emailVerified,
        raw: payload
    };
}
