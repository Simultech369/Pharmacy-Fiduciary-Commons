const { expect } = require("chai");
const fs = require("node:fs");
const path = require("node:path");

describe("Dashboard credibility guardrails", function () {
  const dashboardPath = path.join(__dirname, "..", "dashboard", "index.html");
  const web3Path = path.join(__dirname, "..", "dashboard", "web3_integration.js");
  const dashboard = fs.readFileSync(dashboardPath, "utf8");
  const web3Integration = fs.readFileSync(web3Path, "utf8");

  it("does not attribute synthetic omission fixtures to real PBMs", function () {
    for (const realCompany of ["CVS Caremark", "Express Scripts", "OptumRx"]) {
      expect(dashboard).not.to.include(realCompany);
    }
    expect(dashboard).to.include('data-provenance="synthetic-fixture"');
    expect(dashboard).to.include("Synthetic fixture; not an estimate about a real company");
  });

  it("requires explicit provenance fields before omission data can render", function () {
    expect(dashboard).to.include("assertDisplayableOmissionDataset(data)");
    for (const field of ["source", "methodology", "verified", "mock"]) {
      expect(dashboard).to.match(new RegExp(`${field}:`));
    }
    expect(dashboard).to.include("(!data.mock && !data.verified)");
  });

  it("renders omission card fields with textContent instead of dynamic innerHTML", function () {
    expect(dashboard).to.include("quarter.textContent = item.q");
    expect(dashboard).to.include("badge.textContent = item.status");
    expect(dashboard).to.include("amount.textContent = item.amount");
    expect(dashboard).to.include("desc.textContent = item.desc");
    expect(dashboard).not.to.match(/card\.innerHTML\s*=/);
  });

  it("renders database sync failures without dynamic innerHTML", function () {
    expect(web3Integration).to.include("statusEl.textContent = `");
    expect(web3Integration).to.include("Profile sync failed: ${dbErr.message}");
    expect(web3Integration).to.include('retryBtn.textContent = "Retry Sync";');
    expect(web3Integration).to.include("statusEl.appendChild(retryBtn);");
    expect(web3Integration).not.to.match(/statusEl\.innerHTML\s*=\s*`[^`]*dbErr\.message/);
  });

  it("keeps the newcomer demo receipt flow visible and labeled", function () {
    expect(dashboard).to.include("First Run Receipt Flow");
    expect(dashboard).to.include("npm.cmd run demo:local");
    expect(dashboard).to.include("cache/local-demo/allocations.json");
    expect(dashboard).to.include("cache/local-demo/merkle.json");
    expect(dashboard).to.include("Contract-backed check");
    expect(dashboard).to.include('data-provenance="guided-local-demo"');
  });
});
