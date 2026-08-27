#!/usr/bin/env python3
"""
Pharmacy Fiduciary Commons - Local Dossier Retrieval Engine

This is a dependency-free, local retrieval harness for repository governance
documents. It provides section-aware chunking, lexical hybrid scoring, simple
domain query expansion, deterministic reranking, and line-anchored citations.

Non-claims:
- It is not PDF/page-number RAG.
- It does not use neural embeddings, ColBERT, or a cross-encoder.
- It is a local proof harness for grounded citation retrieval, not production
  knowledge infrastructure.
"""

import argparse
import json
import math
import os
import re
import sys
from collections import Counter

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TARGET_DOCUMENTS = [
    "README.md",
    "ONBOARDING.md",
    "ROADMAP.md",
    "COMMONS_CONSTITUTION.md",
    "AGENT_REVIEW_ORCHESTRATION.md",
    "PORTABILITY.md",
    "SECURITY.md",
    "docs/design/CARE_CONTINUITY.md",
    "docs/design/IDENTITY_NULLIFIER_DESIGN.md",
    "docs/design/PATIENT_FUND_POLICY.md",
    "docs/design/PROVIDER_SELECTION.md",
    "docs/design/RETALIATION_AND_PRIVACY_THREAT_MODEL.md",
    "docs/design/SCARCITY_GOVERNANCE.md",
    "docs/design/SOLVENCY_DEBT_SEMANTICS.md",
    "docs/design/ZK_NULLIFIER_TRANSITION_REQUIREMENTS.md",
    "docs/handoffs/NEXT_REVIEW_HANDOFF.md",
    "docs/ops/EVIDENCE_METADATA.md",
    "docs/ops/MECHANISM_COVERAGE.md",
    "docs/ops/OPEN_DESIGN_DECISIONS.md",
    "docs/ops/PRODUCTION_READINESS_CHECKLIST.md",
    "docs/ops/REVIEW_ITERATION_PROCESS.md",
    "docs/ops/SCANNER_TRIAGE.md",
    "docs/ops/SOLIDITYSCAN_TRIAGE.md",
    "docs/ops/SOLVENCY_OWNER_DECISION_WORKSHEET.md",
    "docs/ops/SOLVENCY_REVIEW_AUTHORITY_AND_SAFETY.md",
    "review-context/SINGLE_REPO_STATE_LEDGER.md",
]

STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "can", "does",
    "for", "from", "how", "if", "in", "is", "it", "of", "on", "or",
    "should", "that", "the", "this", "to", "what", "when", "where",
    "which", "who", "why", "with",
}

QUERY_EXPANSIONS = {
    "previewfinalize": ["dryrunfinalize", "issufficient", "underbacked", "shortfall", "debt", "finalization"],
    "dryrunfinalize": ["previewfinalize", "issufficient", "underbacked", "shortfall", "debt"],
    "issufficient": ["previewfinalize", "dryrunfinalize", "liquidity", "shortfall", "underbacked"],
    "underfunding": ["underbacked", "shortfall", "debt", "liquidity", "deficit"],
    "underfunded": ["underbacked", "shortfall", "debt", "liquidity", "deficit"],
    "evidencehash": ["evidence", "commitment", "preimage", "availability", "interpretation"],
    "evidence": ["evidencehash", "commitment", "preimage", "availability", "interpretation"],
    "zk": ["zero", "knowledge", "nullifier", "unlinkable", "privacy", "fixture", "mock"],
    "privacy": ["zk", "nullifier", "unlinkable", "metadata", "retaliation", "credential"],
    "nullifier": ["zk", "credential", "membership", "unlinkable", "witness", "replay"],
    "provider": ["supabase", "cloudflare", "firebase", "clerk", "auth", "database"],
    "auth": ["provider", "supabase", "clerk", "identity", "session", "rls"],
    "rls": ["supabase", "row", "level", "security", "tenant", "isolation"],
    "tenant": ["rls", "supabase", "isolation", "database", "claim"],
    "offline": ["voucher", "continuity", "non", "digital", "paper", "connectivity"],
    "nondigital": ["offline", "voucher", "paper", "trusted", "proxy", "continuity"],
    "non": ["offline", "digital", "paper", "trusted", "proxy"],
    "reviewer": ["model", "script", "human", "advisory", "authorize", "governance"],
    "model": ["reviewer", "advisory", "human", "authorize", "governance", "script"],
    "automation": ["dry", "run", "human", "gate", "script", "advisory"],
    "readiness": ["production", "launch", "checklist", "mainnet", "prototype", "gate"],
    "mainnet": ["production", "readiness", "launch", "audit", "custody", "gate"],
    "retaliation": ["privacy", "payer", "pbm", "pharmacy", "identity", "metadata"],
    "solvencycheck": ["solvency", "issolvent", "delta", "expectedbalance", "actualbalance", "obligations", "shortfall"],
    "issolvent": ["solvencycheck", "solvent", "delta", "expectedbalance", "actualbalance", "solvency"],
    "capacitycovers": ["capacity", "credit", "limit", "mutual", "voucher", "reservation"],
    "slither": ["static", "analysis", "detector", "triage", "audit", "scanner", "skip"],
    "depositrebate": ["deposit", "rebate", "fee", "transfer", "delta", "tokentransferamountmismatch"],
}


def tokenize(text):
    raw_tokens = re.findall(r"[a-z0-9][a-z0-9_+-]*", text.lower())
    return [token for token in raw_tokens if token not in STOPWORDS and len(token) > 1]


def expand_query_tokens(query):
    tokens = tokenize(query)
    expanded = list(tokens)
    query_lower = query.lower()

    phrase_expansions = {
        "zero knowledge": ["zk", "nullifier", "unlinkable", "privacy"],
        "row level security": ["rls", "supabase", "tenant", "isolation"],
        "non digital": ["nondigital", "offline", "paper", "continuity"],
        "patient fund": ["matching", "participatory", "budgeting", "claim", "share"],
        "model review": ["reviewer", "advisory", "human", "governance"],
        "page number": ["citation", "source", "line", "section"],
        "fee on transfer": ["fee-on-transfer", "delta", "tokentransferamountmismatch", "short-paid", "rebase"],
        "brand gate": ["inline", "style", "extraction", "compliance", "design-system"],
        "dispute timeout": ["retract", "retraction", "flagged", "30", "delay"],
        "mutual credit": ["credit", "limit", "capacity", "voucher", "zero-sum"],
        "sensitivity tiers": ["public_safe", "internal_no_train_ok", "zdr_required", "local_only_required", "compiler"],
    }
    for phrase, additions in phrase_expansions.items():
        if phrase in query_lower:
            expanded.extend(additions)

    for token in tokens:
        expanded.extend(QUERY_EXPANSIONS.get(token, []))

    return expanded


def compute_tf(tokens):
    total = len(tokens)
    if total == 0:
        return {}
    counts = Counter(tokens)
    return {word: count / total for word, count in counts.items()}


def section_title_from_heading(line):
    match = re.match(r"^\s{0,3}#{1,6}\s+(.*?)\s*$", line)
    return match.group(1).strip() if match else None


def split_markdown_sections(lines):
    sections = []
    current = {
        "title": "Preamble",
        "start_line": 1,
        "lines": [],
    }

    for line_no, line in enumerate(lines, start=1):
        heading_title = section_title_from_heading(line)
        if heading_title and current["lines"]:
            sections.append(current)
            current = {
                "title": heading_title,
                "start_line": line_no,
                "lines": [line],
            }
        else:
            if heading_title and not current["lines"]:
                current["title"] = heading_title
                current["start_line"] = line_no
            current["lines"].append(line)

    if current["lines"]:
        sections.append(current)

    return sections


def chunk_section(section, relative_path, max_tokens=500, overlap=50):
    chunks = []
    current_lines = []
    current_word_count = 0
    start_line = section["start_line"]

    for offset, line in enumerate(section["lines"]):
        line_no = section["start_line"] + offset
        word_count = len(line.split())

        if current_word_count + word_count > max_tokens and current_lines:
            end_line = line_no - 1
            chunk_text = "".join(current_lines)
            chunks.append(make_chunk(relative_path, start_line, end_line, section["title"], chunk_text))

            overlap_words = 0
            overlap_lines = []
            for rev_line in reversed(current_lines):
                rev_word_count = len(rev_line.split())
                if overlap_words + rev_word_count <= overlap:
                    overlap_words += rev_word_count
                    overlap_lines.insert(0, rev_line)
                else:
                    break

            current_lines = overlap_lines
            current_word_count = overlap_words
            start_line = max(section["start_line"], line_no - len(overlap_lines))

        current_lines.append(line)
        current_word_count += word_count

    if current_lines:
        end_line = section["start_line"] + len(section["lines"]) - 1
        chunk_text = "".join(current_lines)
        chunks.append(make_chunk(relative_path, start_line, end_line, section["title"], chunk_text))

    return chunks


def make_chunk(relative_path, start_line, end_line, section_title, text):
    search_text = f"{section_title}\n{text}"
    return {
        "relative_path": relative_path,
        "start_line": start_line,
        "end_line": end_line,
        "section_title": section_title,
        "text": text,
        "tokens": tokenize(search_text),
        "title_tokens": tokenize(section_title),
    }


def chunk_document(file_path, relative_path, max_tokens=500, overlap=50):
    if not os.path.exists(file_path):
        return []

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    chunks = []
    for section in split_markdown_sections(lines):
        chunks.extend(chunk_section(section, relative_path, max_tokens=max_tokens, overlap=overlap))

    return chunks


def build_index():
    all_chunks = []
    doc_freqs = Counter()

    for doc in TARGET_DOCUMENTS:
        full_path = os.path.join(REPO_ROOT, doc)
        chunks = chunk_document(full_path, doc)
        for chunk in chunks:
            all_chunks.append(chunk)
            unique_terms = set(chunk["tokens"])
            for term in unique_terms:
                doc_freqs[term] += 1

    num_chunks = max(1, len(all_chunks))
    idf = {term: math.log((num_chunks + 1) / (df + 1)) + 1.0 for term, df in doc_freqs.items()}

    return all_chunks, idf


def score_chunk(query_tokens, original_query_tokens, query_text, chunk, idf, alpha=0.58):
    chunk_tokens = chunk["tokens"]
    if not chunk_tokens or not query_tokens:
        return 0.0

    tf = compute_tf(chunk_tokens)
    query_counts = Counter(query_tokens)
    query_tf = {term: count / len(query_tokens) for term, count in query_counts.items()}

    dot_product = 0.0
    query_norm_sq = 0.0
    chunk_norm_sq = 0.0

    for term, q_tf in query_tf.items():
        term_idf = idf.get(term, 1.0)
        q_val = q_tf * term_idf
        query_norm_sq += q_val * q_val
        if term in tf:
            c_val = tf[term] * term_idf
            dot_product += q_val * c_val

    for term, c_tf in tf.items():
        term_idf = idf.get(term, 1.0)
        c_val = c_tf * term_idf
        chunk_norm_sq += c_val * c_val

    query_norm = math.sqrt(query_norm_sq)
    chunk_norm = math.sqrt(chunk_norm_sq)
    dense_score = dot_product / (query_norm * chunk_norm) if query_norm and chunk_norm else 0.0

    unique_query_tokens = set(query_tokens)
    unique_original_tokens = set(original_query_tokens)
    unique_chunk_tokens = set(chunk_tokens)
    sparse_score = len(unique_query_tokens & unique_chunk_tokens) / max(1, len(unique_query_tokens))
    original_overlap = len(unique_original_tokens & unique_chunk_tokens) / max(1, len(unique_original_tokens))
    title_score = len(unique_query_tokens & set(chunk["title_tokens"])) / max(1, len(unique_query_tokens))

    query_terms = [term for term in original_query_tokens if len(term) >= 4]
    chunk_text_lower = chunk["text"].lower()
    phrase_hits = sum(1 for term in query_terms if term in chunk_text_lower)
    phrase_score = phrase_hits / max(1, len(query_terms))

    base_score = alpha * dense_score + (1.0 - alpha) * sparse_score
    rerank_bonus = (0.16 * original_overlap) + (0.12 * title_score) + (0.08 * phrase_score)
    if os.path.basename(chunk["relative_path"]).lower() in query_text.lower():
        rerank_bonus += 0.1

    return base_score + rerank_bonus


def original_overlap_count(original_query_tokens, chunk):
    return len(set(original_query_tokens) & set(chunk["tokens"]))


def best_snippet(chunk, query_tokens):
    best_line = ""
    best_score = -1
    query_set = set(query_tokens)

    for line in chunk["text"].splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        line_tokens = set(tokenize(stripped))
        score = len(query_set & line_tokens)
        if score > best_score:
            best_score = score
            best_line = stripped

    return best_line[:160]


def file_url(relative_path, start_line, end_line):
    abs_path = os.path.abspath(os.path.join(REPO_ROOT, relative_path)).replace(os.sep, "/")
    return f"file:///{abs_path}#L{start_line}-L{end_line}"


def rag_query(query, top_k=5, min_score=0.15):
    original_query_tokens = tokenize(query)
    query_tokens = expand_query_tokens(query)
    chunks, idf = build_index()

    unique_orig_count = len(set(original_query_tokens))
    min_required_overlap = 2 if unique_orig_count >= 3 else 1
    if unique_orig_count >= 6:
        min_required_overlap = max(3, math.ceil(unique_orig_count * 0.40))

    scored_chunks = []
    for chunk in chunks:
        overlap_count = original_overlap_count(original_query_tokens, chunk)
        if overlap_count < min_required_overlap:
            continue
        score = score_chunk(query_tokens, original_query_tokens, query.lower(), chunk, idf)
        if score >= min_score:
            scored_chunks.append((score, chunk))

    scored_chunks.sort(key=lambda item: item[0], reverse=True)
    top_results = scored_chunks[:top_k]

    results = []
    for score, chunk in top_results:
        citation_url = file_url(chunk["relative_path"], chunk["start_line"], chunk["end_line"])
        results.append({
            "score": round(score, 4),
            "confidence": round(min(1.0, score), 4),
            "file": chunk["relative_path"],
            "section_title": chunk["section_title"],
            "start_line": chunk["start_line"],
            "end_line": chunk["end_line"],
            "line_range": f"L{chunk['start_line']}-L{chunk['end_line']}",
            "source_url": citation_url,
            "page_number": None,
            "citation": f"[`{chunk['relative_path']}:L{chunk['start_line']}-L{chunk['end_line']}`]({citation_url})",
            "snippet": best_snippet(chunk, original_query_tokens or query_tokens),
        })

    return results


def parse_args():
    parser = argparse.ArgumentParser(description="Local line-cited dossier retrieval engine")
    parser.add_argument("--query", type=str, required=True, help="Query string to search in governance dossier")
    parser.add_argument("--top-k", type=int, default=5, help="Number of top results to return")
    parser.add_argument("--min-score", type=float, default=0.15, help="Minimum score for a result to be returned")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    return parser.parse_args()


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    args = parse_args()
    results = rag_query(args.query, top_k=args.top_k, min_score=args.min_score)

    if args.json:
        print(json.dumps({
            "query": args.query,
            "top_k": args.top_k,
            "min_score": args.min_score,
            "result_count": len(results),
            "results": results,
        }, indent=2))
        return

    print("")
    print("==================================================")
    print(f"LOCAL DOSSIER RETRIEVAL QUERY: '{args.query}'")
    print("==================================================")

    if not results:
        print("No matching governance passages found.")
        return

    for index, result in enumerate(results, start=1):
        print("")
        print(f"[{index}] Score: {result['score']} | Citation: {result['citation']}")
        print(f"    Section: {result['section_title']}")
        print(f"    Excerpt: {result['snippet']}")

    print("")
    print("==================================================")
    print("")


if __name__ == "__main__":
    main()
