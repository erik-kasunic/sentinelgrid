import { describe, expect, it } from "vitest";
import { dedupeRelationships } from "./correlate.server";

describe("dedupeRelationships", () => {
  it("merges host names that differ only by the root dot or case", () => {
    const graph = dedupeRelationships([
      {
        fromValue: "208.94.116.246",
        fromType: "ip",
        toValue: "wicarmalware.nfshost.com.",
        toType: "domain",
        kind: "associated_with",
        source: "dns",
      },
      {
        fromValue: "208.94.116.246",
        fromType: "ip",
        toValue: "WicarMalware.nfshost.com",
        toType: "domain",
        kind: "associated_with",
        source: "vt_relations",
      },
    ]);
    expect(graph).toHaveLength(1);
    expect(graph[0]?.toValue).toBe("wicarmalware.nfshost.com");
    expect(graph[0]?.source).toBe("dns, vt_relations");
  });
});
