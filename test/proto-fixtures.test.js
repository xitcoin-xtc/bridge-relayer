import assert from "node:assert/strict";
import test from "node:test";
import { existsSync, readdirSync, readFileSync } from "node:fs";

// Chain and SDK schemas the Xitcoin encoders depend on, kept verbatim as test
// fixtures: the bridge and eth_secp256k1 files from the pos-chain commit
// pinned in test/fixtures/xitcoin-chain-vectors.json, the SDK files from the
// Cosmos SDK module version that commit pins. CI checks every file byte for
// byte against those sources (scripts/check-chain-fixtures.sh).
const fixture = (name) => readFileSync(new URL(`./fixtures/proto/${name}`, import.meta.url), "utf8");
function fields(schema, message) {
  const body = schema.match(new RegExp(`^message ${message} \\{([\\s\\S]*?)^\\}`, "m"))?.[1];
  assert.ok(body, message);
  return Object.fromEntries([...body.matchAll(/^\s*(repeated\s+)?([\w.]+)\s+(\w+)\s*=\s*(\d+)/gm)]
    .map(([, repeated, type, name, number]) => [name, `${repeated ? "repeated " : ""}${type} ${number}`]));
}
const nested = (schema, message) => schema.match(new RegExp(`^  message ${message} \\{([\\s\\S]*?)^  \\}`, "m"))?.[1];

test("proto fixtures live under test/fixtures/proto with the current organization", () => {
  assert.equal(existsSync(new URL("../docs/evidence", import.meta.url)), false);
  assert.deepEqual(readdirSync(new URL("./fixtures/proto/", import.meta.url)).sort(), ["cosmos-sdk-abci.proto",
    "cosmos-sdk-tx-service.proto", "cosmos-sdk-tx.proto", "ethsecp256k1-keys.proto", "xitcoin-bridge.proto",
    "xitcoin-query.proto", "xitcoin-tx.proto"]);
  for (const name of ["xitcoin-tx.proto", "xitcoin-query.proto", "xitcoin-bridge.proto"]) {
    assert.match(fixture(name), /^option go_package = "github\.com\/xitcoin-xtc\/pos-chain\/x\/bridge\/types";$/m);
    assert.doesNotMatch(fixture(name), /xitcoin-org/);
  }
  assert.match(fixture("ethsecp256k1-keys.proto"), /^package cosmos\.evm\.crypto\.v1\.ethsecp256k1;$/m);
  assert.match(fixture("cosmos-sdk-tx.proto"), /^package cosmos\.tx\.v1beta1;$/m);
  assert.match(fixture("cosmos-sdk-tx-service.proto"), /^package cosmos\.tx\.v1beta1;$/m);
  assert.match(fixture("cosmos-sdk-abci.proto"), /^package cosmos\.base\.abci\.v1beta1;$/m);
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

test("typed attestation and route queries carry the processing record and the answering height", () => {
  const query = fixture("xitcoin-query.proto");
  assert.match(query, /get =\s*"\/xitcoin\/bridge\/v1\/attestations\/\{attestation_id\}"/);
  assert.match(query, /get = "\/xitcoin\/bridge\/v1\/routes\/\{route_id\}"/);
  assert.deepEqual(fields(query, "QueryAttestationResponse"),
    { attestation_id: "string 1", status: "AttestationState 2", processed: "bool 3", record: "AttestationRecord 4", height: "int64 5" });
  assert.match(query, /ATTESTATION_STATE_ABSENT = 1;\s[\s\S]*ATTESTATION_STATE_PROCESSED = 2;[\s\S]*ATTESTATION_STATE_PROCESSED_WITHOUT_RECORD = 3;/);
  assert.deepEqual(fields(query, "Route"), { route_id: "string 1", source_chain_id: "string 2", bridge_signers: "repeated string 3",
    guardian: "string 4", max_transfer_amount: "string 5", daily_limit: "string 6", max_outstanding_amount: "string 7",
    enabled: "bool 8", paused: "bool 9", signer_set_version: "uint64 10", control_nonce: "uint64 11", outbound_nonce: "uint64 12" });
  assert.deepEqual(fields(fixture("xitcoin-bridge.proto"), "AttestationRecord"), { attestation_id: "string 1", route_id: "string 2",
    direction: "string 3", source_chain_id: "string 4", source_ref: "string 5", nonce: "uint64 6", recipient: "string 7",
    amount: "string 8", deadline_unix: "int64 9", signer_set_version: "uint64 10", approvers: "repeated string 11",
    destination_chain_id: "string 12", payload_hash: "string 13", signing_digest: "string 14", height: "int64 15", tx_hash: "string 16" });
});

test("SIGN_MODE_DIRECT envelope, eth_secp256k1 key and simulation schemas keep their field numbers", () => {
  const tx = fixture("cosmos-sdk-tx.proto");
  assert.deepEqual(fields(tx, "TxRaw"), { body_bytes: "bytes 1", auth_info_bytes: "bytes 2", signatures: "repeated bytes 3" });
  assert.deepEqual(fields(tx, "SignDoc"), { body_bytes: "bytes 1", auth_info_bytes: "bytes 2", chain_id: "string 3", account_number: "uint64 4" });
  assert.deepEqual(fields(tx, "TxBody"), { messages: "repeated google.protobuf.Any 1", memo: "string 2", timeout_height: "uint64 3",
    unordered: "bool 4", timeout_timestamp: "google.protobuf.Timestamp 5", extension_options: "repeated google.protobuf.Any 1023",
    non_critical_extension_options: "repeated google.protobuf.Any 2047" });
  assert.deepEqual(fields(tx, "AuthInfo"), { signer_infos: "repeated SignerInfo 1", fee: "Fee 2", tip: "Tip 3" });
  assert.deepEqual(fields(tx, "SignerInfo"), { public_key: "google.protobuf.Any 1", mode_info: "ModeInfo 2", sequence: "uint64 3" });
  assert.deepEqual(fields(tx, "Fee"), { amount: "repeated cosmos.base.v1beta1.Coin 1", gas_limit: "uint64 2", payer: "string 3", granter: "string 4" });
  assert.match(nested(tx, "Single") ?? "", /cosmos\.tx\.signing\.v1beta1\.SignMode mode = 1;/);
  assert.match(tx, /Single single = 1;/);
  assert.deepEqual(fields(fixture("ethsecp256k1-keys.proto"), "PubKey"), { key: "bytes 1" });
  assert.deepEqual(fields(fixture("cosmos-sdk-tx-service.proto"), "SimulateRequest"), { tx: "cosmos.tx.v1beta1.Tx 1", tx_bytes: "bytes 2" });
  assert.deepEqual(fields(fixture("cosmos-sdk-tx-service.proto"), "SimulateResponse"),
    { gas_info: "cosmos.base.abci.v1beta1.GasInfo 1", result: "cosmos.base.abci.v1beta1.Result 2" });
  assert.deepEqual(fields(fixture("cosmos-sdk-abci.proto"), "GasInfo"), { gas_wanted: "uint64 1", gas_used: "uint64 2" });
});
