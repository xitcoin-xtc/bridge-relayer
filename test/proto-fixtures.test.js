import assert from "node:assert/strict";
import test from "node:test";
import { existsSync, readFileSync } from "node:fs";

// Pinned chain and SDK schemas, kept as test fixtures. The bridge files are
// verbatim pos-chain 5ec8692e8fc1813d0892ee535af1a73953a1c4fb except for the
// go_package option, which names the current xitcoin-xtc organization.
const fixture = (name) => readFileSync(new URL(`./fixtures/proto/${name}`, import.meta.url), "utf8");
function fields(schema, message) {
  const body = schema.match(new RegExp(`^message ${message} \\{([\\s\\S]*?)^\\}`, "m"))?.[1];
  assert.ok(body, message);
  return Object.fromEntries([...body.matchAll(/^\s*(repeated\s+)?(\w+)\s+(\w+)\s*=\s*(\d+)/gm)]
    .map(([, repeated, type, name, number]) => [name, `${repeated ? "repeated " : ""}${type} ${number}`]));
}

test("proto fixtures live under test/fixtures/proto with the current organization", () => {
  assert.equal(existsSync(new URL("../docs/evidence", import.meta.url)), false);
  for (const name of ["xitcoin-tx.proto", "xitcoin-query.proto"]) {
    assert.match(fixture(name), /^option go_package = "github\.com\/xitcoin-xtc\/pos-chain\/x\/bridge\/types";$/m);
    assert.doesNotMatch(fixture(name), /xitcoin-org/);
  }
  assert.match(fixture("cosmos-sdk-tx-v0.54.4.proto"), /^package cosmos\.tx\.v1beta1;$/m);
});

test("offline attestation encoding uses the pinned MsgSubmitAttestation field numbers and types", () => {
  // src/xitcoin-destination.js writes length-delimited fields 1-5, 7, 8 and 10,
  // varint field 6 (tag 0x30) and varint field 9 (tag 0x48).
  assert.deepEqual(fields(fixture("xitcoin-tx.proto"), "MsgSubmitAttestation"), {
    submitter: "string 1", route_id: "string 2", direction: "string 3", source_chain_id: "string 4",
    source_ref: "string 5", nonce: "uint64 6", destination: "string 7", amount: "string 8",
    deadline_unix: "int64 9", signatures: "repeated bytes 10",
  });
  assert.deepEqual(fields(fixture("xitcoin-query.proto"), "QueryAttestationStatusResponse"),
    { attestation_id: "string 1", processed: "bool 2" });
});
