import { describe, expect, it, vi } from "vitest";
import {
    createGoogleAuthorizationUrl,
    createMicrosoftAuthorizationUrl,
    validateGoogleAuthorizationCode,
    validateMicrosoftAuthorizationCode,
    getGoogleUserInfo,
    getMicrosoftUserInfo,
    decodeJwt
} from "../src/optimized-sso";
import { base64Url } from "@better-auth/utils/base64";

// Mock fetch for tests
global.fetch = vi.fn();

describe("Optimized SSO - Authorization URLs", () => {
    it("should generate a Google authorization URL", async () => {
        const options = {
            clientId: "google-client-id",
            redirectURI: "http://localhost:3000/callback",
        };
        const url = await createGoogleAuthorizationUrl(options, "random-state", "random-verifier");

        expect(url.origin).toBe("https://accounts.google.com");
        expect(url.pathname).toBe("/o/oauth2/v2/auth");
        expect(url.searchParams.get("client_id")).toBe("google-client-id");
        expect(url.searchParams.get("redirect_uri")).toBe("http://localhost:3000/callback");
        expect(url.searchParams.get("state")).toBe("random-state");
        expect(url.searchParams.get("code_challenge")).toBeDefined();
        expect(url.searchParams.get("scope")).toContain("email profile openid");
    });

    it("should generate a Microsoft authorization URL", async () => {
        const options = {
            clientId: "microsoft-client-id",
            redirectURI: "http://localhost:3000/callback",
            tenantId: "my-tenant",
        };
        const url = await createMicrosoftAuthorizationUrl(options, "ms-state", "ms-verifier");

        expect(url.origin).toBe("https://login.microsoftonline.com");
        expect(url.pathname).toBe("/my-tenant/oauth2/v2.0/authorize");
        expect(url.searchParams.get("client_id")).toBe("microsoft-client-id");
        expect(url.searchParams.get("redirect_uri")).toBe("http://localhost:3000/callback");
        expect(url.searchParams.get("state")).toBe("ms-state");
        expect(url.searchParams.get("code_challenge")).toBeDefined();
        expect(url.searchParams.get("scope")).toContain("openid profile email");
    });
});

describe("Optimized SSO - Token Validation", () => {
    it("should validate Google authorization code", async () => {
        const mockResponse = {
            access_token: "mock-access-token",
            id_token: "mock-id-token",
            expires_in: 3600
        };

        vi.mocked(fetch).mockResolvedValueOnce({
            ok: true,
            json: async () => mockResponse,
            text: async () => JSON.stringify(mockResponse)
        } as any);

        const options = {
            clientId: "google-client-id",
            clientSecret: "google-client-secret",
            redirectURI: "http://localhost:3000/callback",
        };

        const tokens = await validateGoogleAuthorizationCode(options, "auth-code", "random-verifier");

        expect(tokens.accessToken).toBe("mock-access-token");
        expect(tokens.idToken).toBe("mock-id-token");
        expect(fetch).toHaveBeenCalledWith(
            "https://oauth2.googleapis.com/token",
            expect.objectContaining({
                method: "POST"
            })
        );
    });

    it("should validate Microsoft authorization code", async () => {
        const mockResponse = {
            access_token: "ms-access-token",
            id_token: "ms-id-token",
            refresh_token: "ms-refresh-token",
            expires_in: 3600
        };

        vi.mocked(fetch).mockResolvedValueOnce({
            ok: true,
            json: async () => mockResponse,
            text: async () => JSON.stringify(mockResponse)
        } as any);

        const options = {
            clientId: "ms-client-id",
            clientSecret: "ms-client-secret",
            redirectURI: "http://localhost:3000/callback",
            tenantId: "common"
        };

        const tokens = await validateMicrosoftAuthorizationCode(options, "auth-code", "ms-verifier");

        expect(tokens.accessToken).toBe("ms-access-token");
        expect(tokens.refreshToken).toBe("ms-refresh-token");
        expect(fetch).toHaveBeenCalledWith(
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            expect.objectContaining({
                method: "POST"
            })
        );
    });
});

describe("Optimized SSO - User Info Extraction", () => {
    // Helper to create a fake JWT string
    function createMockJwt(payload: any) {
        const header = base64Url.encode(new TextEncoder().encode(JSON.stringify({ alg: "HS256" })), { padding: false });
        const body = base64Url.encode(new TextEncoder().encode(JSON.stringify(payload)), { padding: false });
        return `${header}.${body}.signature`;
    }

    it("should decode Google user info from id token", async () => {
        const mockPayload = {
            sub: "12345",
            email: "test@google.com",
            name: "Test User",
            picture: "https://google.com/pic.jpg",
            email_verified: true
        };
        const fakeJwt = createMockJwt(mockPayload);

        const userInfo = await getGoogleUserInfo({ accessToken: "abc", idToken: fakeJwt, raw: {} });

        expect(userInfo.id).toBe("12345");
        expect(userInfo.email).toBe("test@google.com");
        expect(userInfo.name).toBe("Test User");
        expect(userInfo.emailVerified).toBe(true);
    });

    it("should decode Microsoft user info from id token", async () => {
        const mockPayload = {
            oid: "ms-123",
            preferred_username: "test@microsoft.com",
            name: "MS Test",
        };
        const fakeJwt = createMockJwt(mockPayload);

        // Mock fetch for the picture so it doesn't fail
        vi.mocked(fetch).mockResolvedValueOnce({
            ok: false,
        } as any);

        const userInfo = await getMicrosoftUserInfo({ accessToken: "abc", idToken: fakeJwt, raw: {} });

        expect(userInfo.id).toBe("ms-123");
        expect(userInfo.email).toBe("test@microsoft.com");
        expect(userInfo.name).toBe("MS Test");
    });
});
