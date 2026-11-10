// Golden vectors that freeze the audit hash byte format.
//
// Every expected value below is a literal, committed constant. They were
// generated once from the implementation and then frozen. A change to `canonical()`, `hashRow()`, the
// HMAC link, the head signature or the compaction anchor that alters even one
// byte of output fails here. Do NOT "fix" a failing vector by regenerating it:
// a changed byte format invalidates every already-persisted audit chain.
//
// Documented quirks frozen on purpose:
// - `metadata` keys are NOT sorted: insertion order is part of the format.
// - `undefined` top-level fields are omitted by JSON.stringify (no `null`).
// - `undefined` values inside metadata are dropped; `null` is kept.

import { afterEach, describe, expect, it, vi } from "vitest";
import type { GenericEndpointContext } from "better-auth";
import {
  canonical,
  compactChain,
  hashRow,
  signChainHead,
  verifyChain,
  writeAudit,
  type AuditRow,
  type AuditRowForHash,
} from "../../src/server/audit/chain";
import { makeAuth } from "../helpers/auth";

const KEY = "golden-vector-chain-key";
const T = 1_700_000_000_000;

const base: AuditRowForHash = {
  orgId: "org_golden",
  seq: 1,
  actorType: "user",
  actorId: "user_1",
  action: "member.invited",
  targetType: "member",
  targetId: "inv_1",
  ip: "127.0.0.1",
  userAgent: "vitest",
  metadata: {},
  createdAt: T,
};

interface Vector {
  name: string;
  row: AuditRowForHash;
  canonical: string;
  /** sha256 hex off GENESIS, no chain key */
  plain: string;
  /** hmac-sha256 off GENESIS with KEY */
  hmac: string;
}

const vectors: Vector[] = [
  {
    name: "basic ascii",
    row: base,
    canonical:
      '{"orgId":"org_golden","seq":1,"actorType":"user","actorId":"user_1","action":"member.invited","targetType":"member","targetId":"inv_1","ip":"127.0.0.1","userAgent":"vitest","metadata":{},"createdAt":1700000000000}',
    plain: "d845a624e469e3fdcd73862e4ae7e02f1e95c319fcfd0afe09b06c157acabc85",
    hmac: "hmac:db2e635639d764d2ebd0479272ce6159bdcf004ff9d1ac79f3b70c91bf389071",
  },
  {
    name: "unicode, escapes and nested metadata",
    row: {
      ...base,
      seq: 2,
      actorId: "ユーザー🦊",
      action: "café.crème",
      ip: "::1",
      userAgent: 'Mozilla/5.0 "q" \\ back\nnl ls \u0001',
      metadata: { b: { z: [1, 2, { y: null }], a: "é" }, a: 1 },
    },
    canonical:
      '{"orgId":"org_golden","seq":2,"actorType":"user","actorId":"ユーザー🦊","action":"café.crème","targetType":"member","targetId":"inv_1","ip":"::1","userAgent":"Mozilla/5.0 \\"q\\" \\\\ back\\nnl ls \\u0001","metadata":{"b":{"z":[1,2,{"y":null}],"a":"é"},"a":1},"createdAt":1700000000000}',
    plain: "83d92ea375aaf7ed787019e851dd3f1991bc96b0e7b7e1ee17f3c4c050f75bcd",
    hmac: "hmac:3d08ad260e1b75ee50638938cd5e65649b95ce40b3dcbefcd8f5651e437836fc",
  },
  {
    name: "metadata key order a,b",
    row: { ...base, seq: 3, metadata: { a: 1, b: 2 } },
    canonical:
      '{"orgId":"org_golden","seq":3,"actorType":"user","actorId":"user_1","action":"member.invited","targetType":"member","targetId":"inv_1","ip":"127.0.0.1","userAgent":"vitest","metadata":{"a":1,"b":2},"createdAt":1700000000000}',
    plain: "849aad0a098d289bbe7d5e828b51f9af6c743d4f8460d9e2703057619d47230b",
    hmac: "hmac:d98388ca573eb07d8d7c8ccd80a63e3fbfcb46868ffb21e38235854821733306",
  },
  {
    name: "metadata key order b,a (differs from a,b)",
    row: { ...base, seq: 3, metadata: { b: 2, a: 1 } },
    canonical:
      '{"orgId":"org_golden","seq":3,"actorType":"user","actorId":"user_1","action":"member.invited","targetType":"member","targetId":"inv_1","ip":"127.0.0.1","userAgent":"vitest","metadata":{"b":2,"a":1},"createdAt":1700000000000}',
    plain: "aaf5a154cf1cfdd32a565d0b33e4988fd88776a1a5ca541ca3b62347363794f3",
    hmac: "hmac:dd64acfc06d64797ab45fb2f382c350cf1369ba5fa4a83fa08109150b7cabc19",
  },
  {
    name: "null fields and null/undefined metadata values",
    row: {
      ...base,
      seq: 4,
      actorId: null,
      targetId: null,
      ip: null,
      userAgent: null,
      metadata: { n: null, u: undefined, nested: { u: undefined, k: 0 } },
    },
    canonical:
      '{"orgId":"org_golden","seq":4,"actorType":"user","actorId":null,"action":"member.invited","targetType":"member","targetId":null,"ip":null,"userAgent":null,"metadata":{"n":null,"nested":{"k":0}},"createdAt":1700000000000}',
    plain: "d29e0de0c6ccab00a43464f334a23a0859971f54665c92bc6a3115aed80e5e75",
    hmac: "hmac:ee9dc083e7d0e1aa06831bdbd3fabb1d77c7fa9d356c28a59973a171749e337a",
  },
  {
    name: "undefined top-level fields are omitted",
    row: {
      ...base,
      seq: 5,
      actorId: undefined,
      targetId: undefined,
      ip: undefined,
      userAgent: undefined,
    } as unknown as AuditRowForHash,
    canonical:
      '{"orgId":"org_golden","seq":5,"actorType":"user","action":"member.invited","targetType":"member","metadata":{},"createdAt":1700000000000}',
    plain: "192f36abf1d9a3a092fc73e5d952ad27faef6590c607c9423339f9884d1e5f48",
    hmac: "hmac:08f048dfefdf13f75c3607a0598281c0b6d8d80f983107093e0acb7d4c10db28",
  },
  {
    name: "created_at epoch 0",
    row: { ...base, seq: 6, createdAt: 0 },
    canonical:
      '{"orgId":"org_golden","seq":6,"actorType":"user","actorId":"user_1","action":"member.invited","targetType":"member","targetId":"inv_1","ip":"127.0.0.1","userAgent":"vitest","metadata":{},"createdAt":0}',
    plain: "36e578815dd2dbba6c50802f8abe7bbfbd09b59f3605e3de2b393bbbc675bfef",
    hmac: "hmac:a978f736755ad748edc86bb50dff91bf893efa5fcdce29859e3bca06cc47bd06",
  },
  {
    name: "created_at epoch ms with millisecond part",
    row: { ...base, seq: 7, createdAt: 1_700_000_000_123 },
    canonical:
      '{"orgId":"org_golden","seq":7,"actorType":"user","actorId":"user_1","action":"member.invited","targetType":"member","targetId":"inv_1","ip":"127.0.0.1","userAgent":"vitest","metadata":{},"createdAt":1700000000123}',
    plain: "6fe7996f51c2e1b0add9bbabd6e1cd9a0f957e7d2883e3202856ff04867b5935",
    hmac: "hmac:f1eaabaff716699ea4c113fc52366a0edef3535de124e566204fa6cf4effdbb9",
  },
  {
    name: "created_at max Date value",
    row: { ...base, seq: 8, createdAt: 8_640_000_000_000_000 },
    canonical:
      '{"orgId":"org_golden","seq":8,"actorType":"user","actorId":"user_1","action":"member.invited","targetType":"member","targetId":"inv_1","ip":"127.0.0.1","userAgent":"vitest","metadata":{},"createdAt":8640000000000000}',
    plain: "25d7d7254d953df46f89a21a7be0714a9286e03c6e08439b36f0b178a0576d77",
    hmac: "hmac:16c335678e2c5c4842c13b6ceaf2b8a3717a75e2981b06b7fd4a0ea933d5094d",
  },
];

describe("audit hash golden vectors: canonical + hashRow", () => {
  for (const v of vectors) {
    it(`${v.name}: canonical string`, () => {
      expect(canonical(v.row)).toBe(v.canonical);
    });
    it(`${v.name}: unkeyed sha256 hex off GENESIS`, async () => {
      await expect(hashRow("GENESIS", v.row)).resolves.toBe(v.plain);
    });
    it(`${v.name}: keyed hmac hex off GENESIS`, async () => {
      await expect(hashRow("GENESIS", v.row, KEY)).resolves.toBe(v.hmac);
    });
  }

  it("metadata key order is part of the format (no sorting)", () => {
    expect(vectors[2]!.canonical).not.toBe(vectors[3]!.canonical);
    expect(vectors[2]!.plain).not.toBe(vectors[3]!.plain);
  });
});

describe("audit hash golden vectors: chain and head signature", () => {
  const steps = [
    {
      canonical:
        '{"orgId":"org_golden","seq":1,"actorType":"user","actorId":"user_1","action":"chain.step1","targetType":"member","targetId":"inv_1","ip":"127.0.0.1","userAgent":"vitest","metadata":{"i":1},"createdAt":1700000000000}',
      prev: "GENESIS",
      hash: "1e0e1af6a17f71670bf52e75e79b9c96688bf5376c6ff351dcafb1be4b64ab5a",
    },
    {
      canonical:
        '{"orgId":"org_golden","seq":2,"actorType":"user","actorId":"user_1","action":"chain.step2","targetType":"member","targetId":"inv_1","ip":"127.0.0.1","userAgent":"vitest","metadata":{"i":2},"createdAt":1700000000000}',
      prev: "1e0e1af6a17f71670bf52e75e79b9c96688bf5376c6ff351dcafb1be4b64ab5a",
      hash: "bdd3d7e558fdd1326b598d4b341aef5768d7198cfc57caf25ac1c716a3a2974e",
    },
    {
      canonical:
        '{"orgId":"org_golden","seq":3,"actorType":"user","actorId":"user_1","action":"chain.step3","targetType":"member","targetId":"inv_1","ip":"127.0.0.1","userAgent":"vitest","metadata":{"i":3},"createdAt":1700000000000}',
      prev: "bdd3d7e558fdd1326b598d4b341aef5768d7198cfc57caf25ac1c716a3a2974e",
      hash: "hmac:bc909aeb9e9e1b98ef78cc52a6e653f9ab7ccc7d04c235a40acf2ec588e57526",
    },
    {
      canonical:
        '{"orgId":"org_golden","seq":4,"actorType":"user","actorId":"user_1","action":"chain.step4","targetType":"member","targetId":"inv_1","ip":"127.0.0.1","userAgent":"vitest","metadata":{"i":4},"createdAt":1700000000000}',
      prev: "hmac:bc909aeb9e9e1b98ef78cc52a6e653f9ab7ccc7d04c235a40acf2ec588e57526",
      hash: "hmac:55dac7c0fc127321a644d496b27a9bbe8106953538758ae82a13f89d6e0ca445",
    },
  ];

  const rowFor = (i: number): AuditRowForHash => ({
    ...base,
    seq: i,
    action: `chain.step${i}`,
    metadata: { i },
  });

  it("an unkeyed then keyed (monotonic upgrade) chain hashes to the frozen values", async () => {
    for (const [index, step] of steps.entries()) {
      const seq = index + 1;
      expect(canonical(rowFor(seq))).toBe(step.canonical);
      const key = seq <= 2 ? undefined : KEY;
      await expect(hashRow(step.prev, rowFor(seq), key)).resolves.toBe(step.hash);
    }
  });

  it("verifyChain accepts the frozen chain with the key", async () => {
    const rows: AuditRow[] = steps.map((s, index) => ({
      ...rowFor(index + 1),
      id: `id_${index + 1}`,
      prevHash: s.prev,
      hash: s.hash,
    }));
    await expect(verifyChain(rows, KEY)).resolves.toEqual({ ok: true });
  });

  it("signChainHead produces the frozen head signature", async () => {
    await expect(
      signChainHead(KEY, { orgId: "org_golden", seq: 4, hash: steps[3]!.hash }),
    ).resolves.toBe("hmac:51c6f1fcf87b0aa8d5fde0438eddd345e5db73d5991bee8d8015dac9162cfd97");
  });
});

describe("audit hash golden vectors: compaction anchor (sqlite/libSQL)", () => {
  const ORG = "org_golden_anchor";
  const input = {
    orgId: ORG,
    actorType: "user" as const,
    actorId: "user_1",
    action: "member.invited",
    targetType: "member",
    targetId: "inv_1",
  };

  const expected = {
    unkeyed: {
      key: undefined as string | undefined,
      h1: "4555e1b6e0f2085136a980f5b1f6bb8ae6d74ccca6a1d2e077acb22fc5964206",
      h2: "c416fc71ddf9349a35951680cbe769ab4ccf9f78ced89aa06c65d5b522aa09b0",
      anchorHash: "740c95e15abf514e15fd69d1baa2b50c60c62117815cd75dc10b54d1c407d784",
      anchorMetadata:
        '{"compactedThroughSeq":1,"compactedCount":1,"lastHash":"4555e1b6e0f2085136a980f5b1f6bb8ae6d74ccca6a1d2e077acb22fc5964206"}',
    },
    keyed: {
      key: KEY as string | undefined,
      h1: "hmac:33961954831a1988631ebf1052a767a121e0d993692dcacd31d0c00e1ad9a8d4",
      h2: "hmac:6be1e0e4c40e189ac356bc4cfbb8784d2de3ee3854a15b5dc640a4eaa3566f52",
      anchorHash: "hmac:b89c80143379ec02dd945efbe99573f525892481469411d7177a8822b886c422",
      anchorMetadata:
        '{"compactedThroughSeq":1,"compactedCount":1,"lastHash":"hmac:33961954831a1988631ebf1052a767a121e0d993692dcacd31d0c00e1ad9a8d4"}',
    },
  };

  afterEach(() => {
    vi.restoreAllMocks();
  });

  for (const mode of ["unkeyed", "keyed"] as const) {
    it(`${mode} chain: rows and the completed anchor hash to the frozen values`, async () => {
      const exp = expected[mode];
      const t = await makeAuth();
      const ctx = { context: await t.auth.$context } as unknown as GenericEndpointContext;
      const opts = exp.key === undefined ? {} : { chainKey: exp.key };

      let now = T;
      vi.spyOn(Date, "now").mockImplementation(() => now);

      const first = await writeAudit(ctx, { ...input, metadata: { n: 1 } }, opts);
      now = T + 1000;
      const second = await writeAudit(ctx, { ...input, metadata: { n: 2 } }, opts);
      expect(first.hash).toBe(exp.h1);
      expect(second.hash).toBe(exp.h2);

      now = T + 2000;
      const result = await compactChain(ctx, ORG, new Date(T + 500), opts);
      expect(result).toEqual({ compactedThroughSeq: 1, compactedCount: 1, lastHash: exp.h1 });

      const rows = await t.client.execute({
        sql: `SELECT seq, action, prev_hash, hash, metadata, created_at FROM audit_event WHERE org_id = ? ORDER BY seq ASC`,
        args: [ORG],
      });
      expect(rows.rows).toHaveLength(2);
      const anchor = rows.rows[0]!;
      expect(Number(anchor.seq)).toBe(0);
      expect(anchor.action).toBe("audit.retention_compacted");
      expect(anchor.prev_hash).toBe(exp.h1);
      expect(Number(anchor.created_at)).toBe(T + 2000);
      expect(JSON.stringify(JSON.parse(String(anchor.metadata)))).toBe(exp.anchorMetadata);
      expect(anchor.hash).toBe(exp.anchorHash);
      expect(rows.rows[1]!.hash).toBe(exp.h2);
    });
  }
});
