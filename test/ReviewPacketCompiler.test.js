const { expect } = require("chai");
const { execSync } = require("child_process");
const path = require("path");
const fs = require("fs");

describe("Permission-Aware Review Packet Compiler", () => {
  const compilerScript = path.join(__dirname, "../scripts/compile_review_packet.py");
  const tempOutput = path.join(__dirname, "../cache/temp_packet_output.json");

  afterEach(() => {
    if (fs.existsSync(tempOutput)) {
      fs.unlinkSync(tempOutput);
    }
  });

  it("compiles PUBLIC_SAFE packet for docs and test files with verified provenance", () => {
    const output = execSync(
      `python "${compilerScript}" --files "docs/ops/KNOWN_FAILURE_POSTMORTEMS.md" "COMMONS_CONSTITUTION.md"`,
      { encoding: "utf-8" }
    );
    const packet = JSON.parse(output);

    expect(packet.receipt_type).to.equal("PacketSensitivityReceipt");
    expect(packet.schema_version).to.equal("pbm.packet_sensitivity_receipt.v2");
    expect(packet.sensitivity_tier).to.equal("PUBLIC_SAFE");
    expect(packet.public_safe_verified).to.be.true;
    expect(packet.private_artifact_count).to.equal(0);
    expect(packet.artifacts).to.have.lengthOf(2);
    expect(packet.artifacts[0].provenance_verified).to.be.true;
    expect(packet.deduplication_strategy).to.equal("CONTENT_SHA256_EXACT_MATCH_WITH_PATH_FALLBACK_FOR_MISSING");
    expect(packet.unique_content_artifact_count).to.equal(2);
    expect(packet.duplicate_artifact_count).to.equal(0);
    expect(packet.review_packet_cache_key_sha256).to.be.a("string").with.lengthOf(64);
    expect(packet.payload_digest).to.be.a("string").with.lengthOf(64);
  });

  it("marks duplicate verified content with a stable content group", () => {
    const output = execSync(
      `python "${compilerScript}" --files "COMMONS_CONSTITUTION.md" "COMMONS_CONSTITUTION.md" "docs/ops/KNOWN_FAILURE_POSTMORTEMS.md"`,
      { encoding: "utf-8" }
    );
    const packet = JSON.parse(output);

    expect(packet.artifacts).to.have.lengthOf(3);
    expect(packet.unique_content_artifact_count).to.equal(2);
    expect(packet.duplicate_artifact_count).to.equal(1);
    expect(packet.artifacts[0].content_group_id).to.equal(packet.artifacts[1].content_group_id);
    expect(packet.artifacts[0].duplicate_of_artifact_id).to.equal(null);
    expect(packet.artifacts[1].duplicate_of_artifact_id).to.equal(packet.artifacts[0].artifact_id);
    expect(packet.artifacts[2].duplicate_of_artifact_id).to.equal(null);
  });

  it("uses an order-independent cache key for the same review packet content", () => {
    const firstOutput = execSync(
      `python "${compilerScript}" --files "docs/ops/KNOWN_FAILURE_POSTMORTEMS.md" "COMMONS_CONSTITUTION.md"`,
      { encoding: "utf-8" }
    );
    const secondOutput = execSync(
      `python "${compilerScript}" --files "COMMONS_CONSTITUTION.md" "docs/ops/KNOWN_FAILURE_POSTMORTEMS.md"`,
      { encoding: "utf-8" }
    );

    const firstPacket = JSON.parse(firstOutput);
    const secondPacket = JSON.parse(secondOutput);
    expect(firstPacket.review_packet_cache_key_sha256).to.equal(secondPacket.review_packet_cache_key_sha256);
    expect(firstPacket.payload_digest).to.not.equal(secondPacket.payload_digest);
  });

  it("escalates tier to INTERNAL_NO_TRAIN_OK when contracts are included", () => {
    const output = execSync(
      `python "${compilerScript}" --files "contracts/PBMRebateTreasury.sol" "docs/ops/KNOWN_FAILURE_POSTMORTEMS.md"`,
      { encoding: "utf-8" }
    );
    const packet = JSON.parse(output);

    expect(packet.sensitivity_tier).to.equal("INTERNAL_NO_TRAIN_OK");
    expect(packet.public_safe_verified).to.be.false;
    expect(packet.private_artifact_count).to.equal(1);
    expect(packet.artifacts[0].path_or_identifier).to.equal("contracts/PBMRebateTreasury.sol");
    expect(packet.artifacts[0].provenance_verified).to.be.true;
  });

  it("escalates tier to ZDR_REQUIRED when circuits are included", () => {
    const output = execSync(
      `python "${compilerScript}" --files "circuits/vote_nullifier.circom" "test/PBMRebateTreasury.security.test.js"`,
      { encoding: "utf-8" }
    );
    const packet = JSON.parse(output);

    expect(packet.sensitivity_tier).to.equal("ZDR_REQUIRED");
    expect(packet.public_safe_verified).to.be.false;
  });

  it("escalates tier to LOCAL_ONLY_REQUIRED when secret/env files are included", () => {
    const output = execSync(
      `python "${compilerScript}" --files ".env.local" "contracts/PBMRebateTreasury.sol"`,
      { encoding: "utf-8" }
    );
    const packet = JSON.parse(output);

    expect(packet.sensitivity_tier).to.equal("LOCAL_ONLY_REQUIRED");
    expect(packet.public_safe_verified).to.be.false;
  });

  it("marks non-existent files as unverified provenance", () => {
    const output = execSync(
      `python "${compilerScript}" --files "non_existent_file.md"`,
      { encoding: "utf-8" }
    );
    const packet = JSON.parse(output);

    expect(packet.artifacts[0].provenance_verified).to.be.false;
    expect(packet.artifacts[0].content_sha256).to.equal(
      "0000000000000000000000000000000000000000000000000000000000000000"
    );
    expect(packet.public_safe_verified).to.be.false;
  });

  it("does not deduplicate unrelated missing files that share the zero content hash", () => {
    const output = execSync(
      `python "${compilerScript}" --files "missing_alpha.md" "missing_beta.md"`,
      { encoding: "utf-8" }
    );
    const packet = JSON.parse(output);

    expect(packet.artifacts[0].content_sha256).to.equal(packet.artifacts[1].content_sha256);
    expect(packet.artifacts[0].content_group_id).to.not.equal(packet.artifacts[1].content_group_id);
    expect(packet.unique_content_artifact_count).to.equal(2);
    expect(packet.duplicate_artifact_count).to.equal(0);
  });

  it("supports --output flag and seals valid canonical JSON digest", () => {
    execSync(
      `python "${compilerScript}" --demo --output "${tempOutput}"`,
      { encoding: "utf-8" }
    );

    expect(fs.existsSync(tempOutput)).to.be.true;
    const packet = JSON.parse(fs.readFileSync(tempOutput, "utf-8"));
    expect(packet.receipt_type).to.equal("PacketSensitivityReceipt");
    expect(packet.artifacts).to.have.lengthOf(3);
    expect(packet.payload_digest).to.be.a("string").with.lengthOf(64);
  });
});
