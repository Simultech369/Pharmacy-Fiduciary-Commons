const { expect } = require("chai");
const { execSync } = require("child_process");
const path = require("path");

describe("Actual-Dispatch Router Receipt Harness", () => {
  const pythonScript = path.join(__dirname, "../scripts/router_harness.py");

  it("verifies local loopback endpoint resolution and produces valid receipt", () => {
    const output = execSync(`python "${pythonScript}" --verify`, {
      env: { ...process.env, DIZZY_CHAT_BACKEND: "local", OPENAI_COMPAT_BASE_URL: "http://127.0.0.1:11434/v1" },
      encoding: "utf-8"
    });

    expect(output).to.include("ACTUAL-DISPATCH ROUTER RECEIPT VERIFIED");
    expect(output).to.include('"endpoint_classification": "loopback"');
    expect(output).to.include('"credential_used": false');
    expect(output).to.include('"derived_from": "actual_dispatch_attempt"');
  });

  it("fails closed when DIZZY_CHAT_BACKEND=local but endpoint points to external cloud", () => {
    try {
      execSync(`python "${pythonScript}" --verify`, {
        env: { ...process.env, DIZZY_CHAT_BACKEND: "local", OPENAI_COMPAT_BASE_URL: "https://api.openai.com/v1" },
        encoding: "utf-8",
        stdio: "pipe"
      });
      expect.fail("Should have failed closed on endpoint classification mismatch");
    } catch (err) {
      const stderr = err.stderr.toString();
      const stdout = err.stdout.toString();
      expect(stderr + stdout).to.include("Endpoint Mismatch Violation");
      expect(stderr + stdout).to.include("classified as 'external_public'");
    }
  });

  it("permits external cloud endpoints when DIZZY_CHAT_BACKEND is set to cloud", () => {
    const output = execSync(`python "${pythonScript}"`, {
      env: { ...process.env, DIZZY_CHAT_BACKEND: "cloud", OPENAI_COMPAT_BASE_URL: "https://openrouter.ai/api/v1" },
      encoding: "utf-8"
    });

    const receipt = JSON.parse(output);
    expect(receipt.endpoint_classification).to.equal("external_public");
    expect(receipt.source_claim).to.equal("DIZZY_CHAT_BACKEND=cloud");
  });

  it("fails closed when an unverified or quarantined model (muse-glimmer) is requested for review pool", () => {
    try {
      execSync(`python "${pythonScript}" --verify --model muse-glimmer`, {
        env: { ...process.env, DIZZY_CHAT_BACKEND: "local", OPENAI_COMPAT_BASE_URL: "http://127.0.0.1:11434/v1" },
        encoding: "utf-8",
        stdio: "pipe"
      });
      expect.fail("Should have barred quarantined model from review pool");
    } catch (err) {
      const output = err.stderr.toString() + err.stdout.toString();
      expect(output).to.include("Unverified Candidate Pool Gate Violation");
      expect(output).to.include("muse-glimmer");
    }
  });

  it("bars transport_usable_pending_json_quality models (openrouter/free) from default active_review pool", () => {
    try {
      execSync(`python "${pythonScript}" --verify --model openrouter/free`, {
        env: { ...process.env, DIZZY_CHAT_BACKEND: "cloud", OPENAI_COMPAT_BASE_URL: "https://openrouter.ai/api/v1" },
        encoding: "utf-8",
        stdio: "pipe"
      });
      expect.fail("Should have barred transport_usable_pending_json_quality model from default active_review pool");
    } catch (err) {
      const output = err.stderr.toString() + err.stdout.toString();
      expect(output).to.include("Unverified Candidate Pool Gate Violation");
      expect(output).to.include("openrouter/free");
    }
  });

  it("permits transport_usable_pending_json_quality models (openrouter/free) when explicit smoke dispatch mode is specified", () => {
    const output = execSync(`python "${pythonScript}" --verify --model openrouter/free --mode smoke`, {
      env: { ...process.env, DIZZY_CHAT_BACKEND: "cloud", OPENAI_COMPAT_BASE_URL: "https://openrouter.ai/api/v1" },
      encoding: "utf-8"
    });
    expect(output).to.include("ACTUAL-DISPATCH ROUTER RECEIPT VERIFIED");
  });
});
