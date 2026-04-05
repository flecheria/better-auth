import { describe, expect, it, vi, beforeEach } from "vitest";
import {
    createSession,
    validateSessionToken,
    invalidateSession,
    invalidateUserSessions,
    createSessionCookie,
    clearSessionCookie,
    getSessionTokenFromCookie
} from "../src/optimized-session";

describe("Optimized Session Management", () => {
    let mockDb: any;
    let mockSchema: any;

    beforeEach(() => {
        mockSchema = {
            session: { token: "session.token", userId: "session.userId" },
            user: { id: "user.id" }
        };

        const mockExecute = vi.fn().mockResolvedValue(true);
        const mockCatch = vi.fn();
        mockExecute.mockReturnValue({ catch: mockCatch });

        const mockGet = vi.fn();
        const mockReturning = vi.fn().mockReturnValue({ get: mockGet });
        const mockValues = vi.fn().mockReturnValue({ returning: mockReturning });

        const mockWhere = vi.fn().mockReturnValue({
            get: mockGet,
            execute: mockExecute
        });

        const mockFrom = vi.fn().mockReturnValue({ where: mockWhere });

        mockDb = {
            insert: vi.fn().mockReturnValue({ values: mockValues }),
            select: vi.fn().mockReturnValue({ from: mockFrom }),
            delete: vi.fn().mockReturnValue({ where: mockWhere })
        };
    });

    describe("createSession", () => {
        it("should create a session with a generated token and default expiration", async () => {
            const mockSession = { id: "123", userId: "user1", token: "token123" };
            mockDb.insert().values().returning().get.mockResolvedValue(mockSession);

            const result = await createSession({ db: mockDb, schema: mockSchema }, "user1");

            expect(result.token).toBeDefined();
            expect(result.session).toEqual(mockSession);
            expect(mockDb.insert).toHaveBeenCalledWith(mockSchema.session);
        });
    });

    describe("validateSessionToken", () => {
        it("should return null if token is empty", async () => {
            const result = await validateSessionToken({ db: mockDb, schema: mockSchema }, "");
            expect(result).toBeNull();
        });

        it("should return null if session not found", async () => {
            mockDb.select().from().where().get.mockResolvedValueOnce(null);
            const result = await validateSessionToken({ db: mockDb, schema: mockSchema }, "invalid-token");
            expect(result).toBeNull();
        });

        it("should return null and delete session if expired", async () => {
            const expiredSession = { id: "123", token: "expired-token", expiresAt: new Date(Date.now() - 1000) };
            mockDb.select().from().where().get.mockResolvedValueOnce(expiredSession);

            const result = await validateSessionToken({ db: mockDb, schema: mockSchema }, "expired-token");

            expect(result).toBeNull();
            expect(mockDb.delete).toHaveBeenCalledWith(mockSchema.session);
        });

        it("should return null if user not found", async () => {
            const validSession = { id: "123", token: "valid-token", userId: "user1", expiresAt: new Date(Date.now() + 10000) };
            mockDb.select().from().where().get.mockResolvedValueOnce(validSession);
            mockDb.select().from().where().get.mockResolvedValueOnce(null); // User not found

            const result = await validateSessionToken({ db: mockDb, schema: mockSchema }, "valid-token");

            expect(result).toBeNull();
        });

        it("should return session and user if valid", async () => {
            const validSession = { id: "123", token: "valid-token", userId: "user1", expiresAt: new Date(Date.now() + 10000) };
            const validUser = { id: "user1", name: "Test User" };

            mockDb.select().from().where().get.mockResolvedValueOnce(validSession);
            mockDb.select().from().where().get.mockResolvedValueOnce(validUser);

            const result = await validateSessionToken({ db: mockDb, schema: mockSchema }, "valid-token");

            expect(result).toEqual({ session: validSession, user: validUser });
        });
    });

    describe("invalidateSession", () => {
        it("should delete session by token", async () => {
            await invalidateSession({ db: mockDb, schema: mockSchema }, "token-to-delete");
            expect(mockDb.delete).toHaveBeenCalledWith(mockSchema.session);
        });
    });

    describe("invalidateUserSessions", () => {
        it("should delete sessions by userId", async () => {
            await invalidateUserSessions({ db: mockDb, schema: mockSchema }, "user1");
            expect(mockDb.delete).toHaveBeenCalledWith(mockSchema.session);
        });
    });
});

describe("Cookie Functions", () => {
    it("should create a session cookie string", () => {
        const expiresAt = new Date(Date.now() + 3600 * 1000);
        const cookie = createSessionCookie("my-token", expiresAt);
        expect(cookie).toContain("better-auth.session_token=my-token");
        expect(cookie).toContain("Max-Age=");
        expect(cookie).toContain("HttpOnly");
        expect(cookie).toContain("Secure");
        expect(cookie).toContain("SameSite=Lax");
        expect(cookie).toContain("Path=/");
    });

    it("should clear a session cookie string", () => {
        const cookie = clearSessionCookie();
        expect(cookie).toContain("better-auth.session_token=; Max-Age=0");
        expect(cookie).toContain("HttpOnly");
        expect(cookie).toContain("Secure");
        expect(cookie).toContain("SameSite=Lax");
        expect(cookie).toContain("Path=/");
    });

    it("should parse session token from cookie header", () => {
        const header = "other_cookie=value; better-auth.session_token=my-secret-token; another=123";
        const token = getSessionTokenFromCookie(header);
        expect(token).toBe("my-secret-token");
    });

    it("should return null if token not in cookie header", () => {
        const header = "other_cookie=value; another=123";
        const token = getSessionTokenFromCookie(header);
        expect(token).toBeNull();
    });

    it("should return null if cookie header is empty", () => {
        const token = getSessionTokenFromCookie(null);
        expect(token).toBeNull();
    });
});
