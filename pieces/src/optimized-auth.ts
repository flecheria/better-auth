import { eq } from "drizzle-orm";
// import { type BetterAuthOptions } from "@better-auth/core"; // Removed, not needed for pure logic implementation
// Removed parseCookies import as it might be problematic if not in core/utils, we can implement it if needed, or just let user provide tokens

// Fake types to replace local imports
type Session = any;
type User = any;

/**
 * optimized-auth.ts
 *
 * This file contains an optimized implementation of authentication functions
 * designed for Cloudflare Workers and Drizzle ORM.
 *
 * It replaces the default Scrypt hashing (which can be CPU intensive on Workers)
 * with Web Crypto API's PBKDF2, which is native and much faster.
 *
 * Usage:
 * Copy this file into your project and adapt the database queries to match your schema.
 */

// --- 1. Web Crypto Password Hashing (PBKDF2) ---

export const WebCryptoPassword = {
    async hash(password: string): Promise<string> {
        const encoder = new TextEncoder();
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const keyMaterial = await crypto.subtle.importKey(
            "raw",
            encoder.encode(password),
            { name: "PBKDF2" },
            false,
            ["deriveBits", "deriveKey"]
        );
        const key = await crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: 100000,
                hash: "SHA-256",
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );

        const exportedKey = await crypto.subtle.exportKey("raw", key);
        const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
        const keyHex = Array.from(new Uint8Array(exportedKey)).map(b => b.toString(16).padStart(2, '0')).join('');

        return `${saltHex}:${keyHex}`;
    },

    async verify(password: string, hash: string): Promise<boolean> {
        const parts = hash.split(':');
        if (parts.length !== 2) return false;

        const [saltHex, keyHex] = parts;
        const salt = new Uint8Array(saltHex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
        const originalKey = new Uint8Array(keyHex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));

        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            "raw",
            encoder.encode(password),
            { name: "PBKDF2" },
            false,
            ["deriveBits", "deriveKey"]
        );

        const key = await crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: 100000,
                hash: "SHA-256",
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );

        const exportedKey = await crypto.subtle.exportKey("raw", key);
        const derivedKey = new Uint8Array(exportedKey);

        if (originalKey.length !== derivedKey.length) return false;

        // Constant-time comparison
        let result = 0;
        for (let i = 0; i < originalKey.length; i++) {
            result |= originalKey[i] ^ derivedKey[i];
        }
        return result === 0;
    }
};

// --- Helper parseCookies ---
export function parseCookies(header: string) {
    const cookies = new Map<string, string>();
    header.split(';').forEach(cookie => {
        const parts = cookie.split('=');
        cookies.set(parts[0].trim(), parts[1] ? parts.slice(1).join('=').trim() : '');
    });
    return cookies;
}

// --- 2. Optimized Auth Functions ---

/**
 * Optimized Sign In with Email
 */
export async function signInEmailOptimized(
    ctx: {
        req: Request;
        db: any; // Drizzle DB instance
        schema: {
            user: any;
            session: any;
            account: any;
        };
    },
    email: string,
    password: string,
    options?: {
        rememberMe?: boolean;
    }
) {
    const { db, schema } = ctx;

    // 1. Find User by Email
    // Adapting this to raw Drizzle query for performance
    const user = await db.select().from(schema.user).where(eq(schema.user.email, email)).get();

    if (!user) {
        // Dummy verification to prevent timing attacks
        await WebCryptoPassword.verify("dummy", "00000000000000000000000000000000:0000000000000000000000000000000000000000000000000000000000000000");
        return { error: "Invalid email or password" };
    }

    // 2. Find Credential Account (assuming standard better-auth schema where password is in account)
    const account = await db.select().from(schema.account)
        .where(eq(schema.account.userId, user.id)) // Assuming 'userId' column
        .get();

    // Check if account exists and is credential provider (if you store multiple providers)
    // Simplified: assuming query returned the right account or you filter in JS
    if (!account || !account.password) {
         await WebCryptoPassword.verify("dummy", "00000000000000000000000000000000:0000000000000000000000000000000000000000000000000000000000000000");
        return { error: "Invalid email or password" };
    }

    // 3. Verify Password
    const isValid = await WebCryptoPassword.verify(password, account.password);

    if (!isValid) {
        return { error: "Invalid email or password" };
    }

    // 4. Create Session
    const token = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + (options?.rememberMe ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000)); // 30 days or 1 day

    const session = await db.insert(schema.session).values({
        id: crypto.randomUUID(),
        userId: user.id,
        token: token,
        expiresAt: expiresAt,
        createdAt: new Date(),
        updatedAt: new Date(),
        ipAddress: ctx.req.headers.get("cf-connecting-ip") || ctx.req.headers.get("x-forwarded-for"),
        userAgent: ctx.req.headers.get("user-agent"),
    }).returning().get();

    // 5. Return Session & Cookie
    return {
        session,
        user,
        cookie: createSessionCookie(token, expiresAt, options?.rememberMe)
    };
}

/**
 * Optimized Sign Out
 */
export async function signOutOptimized(
    ctx: {
        req: Request;
        db: any;
        schema: {
            session: any;
        };
    }
) {
    const cookieHeader = ctx.req.headers.get("Cookie");
    if (!cookieHeader) return { success: true };

    const cookies = parseCookies(cookieHeader);
    const sessionToken = cookies.get("better-auth.session_token");

    if (sessionToken) {
        await ctx.db.delete(ctx.schema.session).where(eq(ctx.schema.session.token, sessionToken)).execute();
    }

    return {
        success: true,
        cookie: "better-auth.session_token=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax"
    };
}

/**
 * Optimized Get Session
 */
export async function getSessionOptimized(
    ctx: {
        req: Request;
        db: any;
        schema: {
            user: any;
            session: any;
        };
    }
) {
    const cookieHeader = ctx.req.headers.get("Cookie");
    if (!cookieHeader) return null;

    const cookies = parseCookies(cookieHeader);
    const sessionToken = cookies.get("better-auth.session_token");

    if (!sessionToken) return null;

    // Direct Join for speed (if supported by your Drizzle adapter/driver)
    // Or two queries
    const session = await ctx.db.select().from(ctx.schema.session)
        .where(eq(ctx.schema.session.token, sessionToken))
        .get();

    if (!session) return null;

    if (new Date(session.expiresAt) < new Date()) {
        // Expired
        // Ideally delete it async
        ctx.db.delete(ctx.schema.session).where(eq(ctx.schema.session.token, sessionToken)).execute().catch(console.error);
        return null;
    }

    const user = await ctx.db.select().from(ctx.schema.user)
        .where(eq(ctx.schema.user.id, session.userId))
        .get();

    if (!user) return null;

    return {
        session,
        user
    };
}

/**
 * Helper to generate a secure machine token and its hash.
 * You send the `secret` to the machine, and store the `hash` in your DB.
 */
export async function createMachineToken(
    userId: string,
    secret: string = crypto.randomUUID()
) {
    const hash = await WebCryptoPassword.hash(secret);
    return {
        secret,
        hash
    };
}

/**
 * Machine to Machine Auth (Stateless / Long-lived)
 *
 * This creates a token that is verified against a hash in the database,
 * avoiding session storage overhead for every request if desired,
 * or just a specialized long-lived session.
 */
export async function signInMachine(
    ctx: {
        db: any;
        schema: {
            // Define your schema for API keys here
        };
    },
    apiKey: string
) {
    // 1. Parse API Key (if you use ID:Secret format)
    // 2. Lookup key in DB
    // 3. Verify hash using WebCryptoPassword.verify(secret, storedHash)

    return { error: "Custom implementation required - See createMachineToken" };
}

// --- Helper Functions ---

function createSessionCookie(token: string, expiresAt: Date, rememberMe?: boolean): string {
    const maxAge = Math.floor((expiresAt.getTime() - Date.now()) / 1000);
    // Basic cookie string construction
    return `better-auth.session_token=${token}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}
