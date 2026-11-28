import { loadSubmitterManifest, verifySubmitterRelease } from "./submitter-manifest.js";

export const SUBMITTER_GAPS = Object.freeze({
  xitcoin: "xitcoin_canonical_transaction_and_status_adapter_missing",
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
    // Offline success is not readiness: chain identity, vault code, signer set,
    // keystore and durable state are verified only by `start`.
    return Object.freeze({ version: 1, destination: manifest.destination, releaseCommit: manifest.releaseCommit,
      mode: "testnet", ready: false, submissions: 0, blocker: "cronos_live_checks_run_only_at_start" });
  }
  return Object.freeze({ version: 1, destination: manifest.destination, releaseCommit: manifest.releaseCommit,
    mode: "disabled", ready: false, submissions: 0, blocker: SUBMITTER_GAPS[manifest.destination] });
}

// Only an explicit root-owned Cronos `testnet` manifest builds a runtime. The
// Xitcoin destination and every disabled manifest refuse, as in phase one.
export async function buildSubmitterRuntime(options, dependencies = {}) {
  const manifest = await verifiedManifest(options, dependencies);
  if (manifest.mode !== "testnet" || manifest.destination !== "cronos") {
    const error = new Error(SUBMITTER_GAPS[manifest.destination]);
    error.code = "SUBMITTER_UNAVAILABLE";
    throw error;
  }
  const { buildCronosSubmitterRuntime } = await import("./cronos-submitter.js");
  const build = dependencies.buildCronos ?? buildCronosSubmitterRuntime;
  return build(manifest, { credentialsDirectory: options.credentialsDirectory, ...dependencies.cronos });
}
