const { expect } = require("chai");
const fs = require("node:fs");
const path = require("node:path");

describe("Dashboard credibility guardrails", function () {
  const dashboardPath = path.join(__dirname, "..", "dashboard", "index.html");
  const dashboard = fs.readFileSync(dashboardPath, "utf8");

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
});
