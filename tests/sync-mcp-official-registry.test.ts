/**
 * Tests for the dedup-key derivation in
 * scripts/sync-mcp-official-registry.ts.
 *
 * The official MCP Registry (registry.modelcontextprotocol.io) returns one
 * ROW per (server name, version) pair -- not one row per unique underlying
 * package. The same npm/PyPI package can appear under many rows: one per
 * published version, and sometimes under more than one reverse-DNS server
 * name. derivePackageIdentities() is the function that collapses rows back
 * to the underlying package identity so the collector writes one file per
 * real package, not one per registry row. These tests pin that behavior.
 *
 * Run with: npx vitest tests/sync-mcp-official-registry.test.ts
 */

import { describe, it, expect } from "vitest";
import {
  derivePackageIdentities,
  sanitizeKeyToFilename,
} from "../scripts/sync-mcp-official-registry.js";

function makeEntry(server: Record<string, unknown>) {
  return {
    server: {
      $schema: "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
      name: "io.example/thing",
      description: "test",
      version: "1.0.0",
      ...server,
    },
  } as any;
}

describe("derivePackageIdentities", () => {
  it("keys an npm package by registryType + identifier, not by server name or version", () => {
    const a = makeEntry({
      name: "io.example/thing-a",
      version: "1.0.0",
      packages: [{ registryType: "npm", identifier: "@scope/thing", transport: { type: "stdio" } }],
    });
    const b = makeEntry({
      name: "io.example/thing-b", // different reverse-DNS name
      version: "2.0.0", // different version
      packages: [{ registryType: "NPM", identifier: "@Scope/Thing", transport: { type: "stdio" } }], // different case
    });
    const idA = derivePackageIdentities(a);
    const idB = derivePackageIdentities(b);
    expect(idA).toHaveLength(1);
    expect(idB).toHaveLength(1);
    expect(idA[0].key).toBe(idB[0].key); // must collapse to the SAME underlying package
    expect(idA[0].type).toBe("package");
    expect(idA[0].key).toBe("pkg:npm:@scope/thing");
  });

  it("emits one identity per distinct package when a server publishes to multiple registries", () => {
    const entry = makeEntry({
      packages: [
        { registryType: "npm", identifier: "thing-server", transport: { type: "stdio" } },
        { registryType: "oci", identifier: "ghcr.io/example/thing-server", transport: { type: "stdio" } },
      ],
    });
    const ids = derivePackageIdentities(entry);
    expect(ids).toHaveLength(2);
    expect(ids.map((i) => i.key).sort()).toEqual([
      "pkg:npm:thing-server",
      "pkg:oci:ghcr.io/example/thing-server",
    ]);
  });

  it("falls back to repository URL when there are no packages (remote-only server with source)", () => {
    const entry = makeEntry({
      repository: { url: "https://github.com/Example/Thing/", source: "github" },
      remotes: [{ type: "streamable-http", url: "https://thing.example.com/mcp" }],
    });
    const ids = derivePackageIdentities(entry);
    expect(ids).toHaveLength(1);
    expect(ids[0].type).toBe("repository");
    // trailing slash and case must normalize so re-registrations collapse
    expect(ids[0].key).toBe("repo:https://github.com/example/thing");
  });

  it("falls back to the remote URL when there is no packages[] and no repository", () => {
    const entry = makeEntry({
      remotes: [{ type: "streamable-http", url: "https://api.example.com/mcp" }],
    });
    const ids = derivePackageIdentities(entry);
    expect(ids).toHaveLength(1);
    expect(ids[0].type).toBe("remote");
    expect(ids[0].key).toBe("remote:https://api.example.com/mcp");
  });

  it("falls back to server name as a last resort for a minimal/malformed entry", () => {
    const entry = makeEntry({ name: "io.example/bare" });
    const ids = derivePackageIdentities(entry);
    expect(ids).toHaveLength(1);
    expect(ids[0].type).toBe("server_name");
    expect(ids[0].key).toBe("servername:io.example/bare");
  });

  it("ignores a packages[] entry missing identifier/registryType rather than crashing", () => {
    const entry = makeEntry({
      packages: [{ transport: { type: "stdio" } } as any],
      repository: { url: "https://github.com/example/thing" },
    });
    // The malformed package entry is filtered out; since packages[] is
    // non-empty the function does not fall through to repository -- this
    // documents current behavior (an entry with only-malformed packages
    // yields zero identities from the package branch).
    const ids = derivePackageIdentities(entry);
    expect(ids).toEqual([]);
  });
});

describe("sanitizeKeyToFilename", () => {
  it("produces a filesystem-safe, deterministic filename with a hash suffix", () => {
    const f1 = sanitizeKeyToFilename("pkg:npm:@scope/thing");
    const f2 = sanitizeKeyToFilename("pkg:npm:@scope/thing");
    expect(f1).toBe(f2); // deterministic
    expect(f1).toMatch(/^[a-z0-9._-]+--[0-9a-f]{8}\.json$/);
    expect(f1).not.toMatch(/[@/:]/);
  });

  it("gives different keys different filenames even if their slugs collapse to the same string", () => {
    // Both sanitize their special chars away to the same slug shape, but the
    // hash suffix must keep them from colliding.
    const f1 = sanitizeKeyToFilename("pkg:npm:foo@bar");
    const f2 = sanitizeKeyToFilename("pkg:npm:foo#bar");
    expect(f1).not.toBe(f2);
  });
});
