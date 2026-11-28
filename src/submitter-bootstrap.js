import { loadSubmitterManifest, verifySubmitterRelease } from "./submitter-manifest.js";

export const SUBMITTER_GAPS = Object.freeze({
  xitcoin: "xitcoin_submission_disabled_by_manifest",
  cronos: "cronos_submission_disabled_by_manifest",
});

async function verifiedManifest({ manifestPath, destination, modulePath }, {
  loadManifest = loadSubmitterManifest, verifyRelease = verifySubmitterRelease,
} = {}) {
  const manifest = await loadManifest(manifestPath);
  // Verification revalidates the complete manifest, including its mode.
  await verifyRelease(manifest, modulePath);
  if (destination !== manifest.destination) throw new Error("submitter destination does not match its manifest");
  return manifest;
}

// Offline inspection only: no store, RPC, credential, signing or broadcast.
export async function inspectSubmitter(options, dependencies) {
  const manifest = await verifiedManifest(options, dependencies);
  if (manifest.mode === "testnet") {
    // Offline success is not readiness: chain identity, route or vault code,
    // signer set, keystore and durable state are verified only by `start`.
    return Object.freeze({ version: 1, destination: manifest.destination, releaseCommit: manifest.releaseCommit,
      mode: "testnet", ready: false, submissions: 0, blocker: `${manifest.destination}_live_checks_run_only_at_start` });
  }
  return Object.freeze({ version: 1, destination: manifest.destination, releaseCommit: manifest.releaseCommit,
    mode: "disabled", ready: false, submissions: 0, blocker: SUBMITTER_GAPS[manifest.destination] });
}

// Only an explicit root-owned `testnet` manifest builds a runtime (Cronos
// chain ID 338 or Xitcoin chain ID xitcoin-testnet-v2-1; both mainnets are
// rejected by the manifest). Every disabled manifest refuses, as in phase one.
export async function buildSubmitterRuntime(options, dependencies = {}) {
  const manifest = await verifiedManifest(options, dependencies);
  if (manifest.mode !== "testnet") {
    const error = new Error(SUBMITTER_GAPS[manifest.destination]);
    error.code = "SUBMITTER_UNAVAILABLE";
    throw error;
  }
  if (manifest.destination === "xitcoin") {
    const { buildXitcoinSubmitterRuntime } = await import("./xitcoin-submitter.js");
    const build = dependencies.buildXitcoin ?? buildXitcoinSubmitterRuntime;
    return build(manifest, { credentialsDirectory: options.credentialsDirectory, ...dependencies.xitcoin });
  }
  const { buildCronosSubmitterRuntime } = await import("./cronos-submitter.js");
  const build = dependencies.buildCronos ?? buildCronosSubmitterRuntime;
  return build(manifest, { credentialsDirectory: options.credentialsDirectory, ...dependencies.cronos });
}
