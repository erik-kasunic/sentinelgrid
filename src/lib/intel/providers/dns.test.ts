import { describe, expect, it } from "vitest";
import { parseAnswers, type DohAnswer } from "./dns.server";

// What a resolver returns for an alias: the CNAME first, then the records of its target.
const aliased: DohAnswer[] = [
  { name: "malware.wicar.org.", type: 5, data: "wicarmalware.nfshost.com." },
  { name: "wicarmalware.nfshost.com.", type: 1, data: "208.94.116.246" },
];

describe("parseAnswers", () => {
  it("keeps only A records for an A query on an alias", () => {
    expect(parseAnswers("A", aliased)).toEqual(["208.94.116.246"]);
  });

  it("does not report the CNAME target as MX, NS or TXT", () => {
    const cnameOnly = aliased.slice(0, 1);
    expect(parseAnswers("MX", cnameOnly)).toEqual([]);
    expect(parseAnswers("NS", cnameOnly)).toEqual([]);
    expect(parseAnswers("TXT", cnameOnly)).toEqual([]);
  });

  it("returns the CNAME without the root dot", () => {
    expect(parseAnswers("CNAME", aliased)).toEqual(["wicarmalware.nfshost.com"]);
  });

  it("unquotes TXT records", () => {
    expect(parseAnswers("TXT", [{ name: "a.com.", type: 16, data: '"v=spf1 -all"' }])).toEqual([
      "v=spf1 -all",
    ]);
  });
});
