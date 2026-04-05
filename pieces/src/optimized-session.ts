import { eq } from "drizzle-orm";

/**
 * optimized-session.ts
 *
 * This file contains an optimized implementation of session management
 * designed for Cloudflare Workers and Drizzle ORM.
 */

// --- 1. Session Functions ---

export async function createSession(
    ctx: {
        db: any;
        schema: {
            session: any;
        };
    },
    userId: string,
    options?: {
        expiresIn?: number; // ms
        ipAddress?: string;
        userAgent?: string;
    }
) {
    const token = crypto.randomUUID();
    const expiresIn = options?.expiresIn || 30 * 24 * 60 * 60 * 1000; // default 30 days
    const expiresAt = new Date(Date.now() + expiresIn);

    const session = await ctx.db.insert(ctx.schema.session).values({
        id: crypto.randomUUID(),
        userId: userId,
        token: token,
        expiresAt: expiresAt,
        createdAt: new Date(),
        updatedAt: new Date(),
        ipAddress: options?.ipAddress || null,
        userAgent: options?.userAgent || null,
    }).returning().get();

    return { session, token };
}

export async function validateSessionToken(
    ctx: {
        db: any;
        schema: {
            user: any;
            session: any;
        };
    },
    token: string
) {
    if (!token) return null;

    const session = await ctx.db.select().from(ctx.schema.session)
        .where(eq(ctx.schema.session.token, token))
        .get();

    if (!session) return null;

    if (new Date(session.expiresAt) < new Date()) {
        // Expired
        ctx.db.delete(ctx.schema.session).where(eq(ctx.schema.session.token, token)).execute().catch(console.error);
        return null;
    }

    const user = await ctx.db.select().from(ctx.schema.user)
        .where(eq(ctx.schema.user.id, session.userId))
        .get();

    if (!user) return null;

    return { session, user };
}

export async function invalidateSession(
    ctx: {
        db: any;
        schema: {
            session: any;
        };
    },
    token: string
) {
    if (!token) return;

    await ctx.db.delete(ctx.schema.session).where(eq(ctx.schema.session.token, token)).execute();
}

export async function invalidateUserSessions(
    ctx: {
        db: any;
        schema: {
            session: any;
        };
    },
    userId: string
) {
    if (!userId) return;

    await ctx.db.delete(ctx.schema.session).where(eq(ctx.schema.session.userId, userId)).execute();
}

// --- 2. Cookie Functions ---

export function createSessionCookie(token: string, expiresAt: Date, options?: { secure?: boolean, domain?: string, path?: string, sameSite?: "Strict" | "Lax" | "None" }): string {
    const maxAge = Math.floor((expiresAt.getTime() - Date.now()) / 1000);
    const secure = options?.secure !== false ? "; Secure" : "";
    const domain = options?.domain ? `; Domain=${options.domain}` : "";
    const path = options?.path ? `; Path=${options.path}` : "; Path=/";
    const sameSite = options?.sameSite ? `; SameSite=${options.sameSite}` : "; SameSite=Lax";

    return `better-auth.session_token=${token}; Max-Age=${maxAge}${path}; HttpOnly${secure}${domain}${sameSite}`;
}

export function clearSessionCookie(options?: { secure?: boolean, domain?: string, path?: string, sameSite?: "Strict" | "Lax" | "None" }): string {
    const secure = options?.secure !== false ? "; Secure" : "";
    const domain = options?.domain ? `; Domain=${options.domain}` : "";
    const path = options?.path ? `; Path=${options.path}` : "; Path=/";
    const sameSite = options?.sameSite ? `; SameSite=${options.sameSite}` : "; SameSite=Lax";

    return `better-auth.session_token=; Max-Age=0${path}; HttpOnly${secure}${domain}${sameSite}`;
}

export function getSessionTokenFromCookie(cookieHeader: string | null): string | null {
    if (!cookieHeader) return null;

    const cookies = new Map<string, string>();
    cookieHeader.split(';').forEach(cookie => {
        const parts = cookie.split('=');
        cookies.set(parts[0].trim(), parts[1] ? parts.slice(1).join('=').trim() : '');
    });

    return cookies.get("better-auth.session_token") || null;
}
