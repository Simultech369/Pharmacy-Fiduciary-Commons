const { expect } = require("chai");
const fs = require("fs");
const path = require("path");

describe("Advanced RAG mapping proof boundaries", function () {
  const repoRoot = path.resolve(__dirname, "..");
  const mappingPath = path.join(repoRoot, "docs", "plans", "advanced_rag_retrieval_mapping.md");
  const mapping = fs.readFileSync(mappingPath, "utf8");

  it("frames the RAG mapping as a proof-bounded roadmap", function () {
    expect(mapping).to.include("DESIGN MAP / PROOF-BOUNDED ROADMAP");
    expect(mapping).to.include("Current local proof");
    expect(mapping).to.include("Explicit Non-Claims");
    expect(mapping).to.include("`scripts/dossier_rag_retrieval.py` is a dependency-free lexical retrieval harness");
  });

  it("records explicit non-claims for unimplemented advanced retrieval techniques", function () {
    expect(mapping).to.include("No neural embedding index, vector database, BM25 library, or reciprocal rank fusion implementation is claimed.");
    expect(mapping).to.include("No cross-encoder, ColBERT, late-interaction model, or learned reranker is claimed.");
    expect(mapping).to.include("No HyDE embedding workflow, automated query decomposition pipeline, CRAG web fallback, or production retrieval self-healing loop is claimed.");
    expect(mapping).to.include("No RAPTOR recursive clustering or GraphRAG community-summary pipeline is claimed.");
  });

  it("does not overclaim prototype lexical retrieval as production RAG", function () {
    expect(mapping).to.include("Not a production benchmark");
    expect(mapping).to.include("No LLM-generated per-chunk context preamble is claimed.");
    expect(mapping).to.include("**Not implemented**: deterministic scoring and failure-memory ranking exist, but no cross-encoder or external reranker is used.");
    expect(mapping).to.not.include("Implemented: Risk evaluator ranks top candidate by failure memory score.");
    expect(mapping).to.not.include("Implemented: Ripgrep exact pattern match fused");
  });
});
