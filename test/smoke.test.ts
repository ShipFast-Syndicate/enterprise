import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { drizzle } from "drizzle-orm/libsql";
import { createClient } from "@libsql/client";

describe("toolchain", () => {
  it("boots better-auth 1.7.5 on libsql :memory:", async () => {
    const client = createClient({ url: ":memory:" });
    const db = drizzle(client);
    const auth = betterAuth({
      database: drizzleAdapter(db, { provider: "sqlite" }),
      secret: "x".repeat(32),
      baseURL: "http://localhost:3000",
      emailAndPassword: { enabled: true },
    });
    const ctx = await auth.$context;
    expect(ctx.options.baseURL).toBe("http://localhost:3000");

    // better-auth's package.json is not in its `exports` map, so a JSON
    // import assertion is blocked by Node's exports enforcement — read it
    // from node_modules directly instead.
    const pkgPath = new URL("../node_modules/better-auth/package.json", import.meta.url);
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { version: string };
    expect(pkg.version).toBe("1.7.5");
  });
});
