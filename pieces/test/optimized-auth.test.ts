import { describe, expect, it } from "vitest";
import { WebCryptoPassword, createMachineToken } from "../src/optimized-auth";

describe("WebCryptoPassword", () => {
    it("should hash and verify a password", async () => {
        const password = "password123";
        const hash = await WebCryptoPassword.hash(password);
        expect(hash).toContain(":");
        const isValid = await WebCryptoPassword.verify(password, hash);
        expect(isValid).toBe(true);
    });

    it("should fail to verify an incorrect password", async () => {
        const password = "password123";
        const hash = await WebCryptoPassword.hash(password);
        const isValid = await WebCryptoPassword.verify("wrongpassword", hash);
        expect(isValid).toBe(false);
    });

    it("should fail to verify with invalid hash format", async () => {
        const isValid = await WebCryptoPassword.verify("password", "invalidhash");
        expect(isValid).toBe(false);
    });
});

describe("createMachineToken", () => {
    it("should create a secret and hash", async () => {
        const result = await createMachineToken("user123");
        expect(result.secret).toBeDefined();
        expect(result.hash).toContain(":");
        const isValid = await WebCryptoPassword.verify(result.secret, result.hash);
        expect(isValid).toBe(true);
    });
});
