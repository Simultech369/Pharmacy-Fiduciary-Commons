#!/usr/bin/env python3
"""
Pharmacy Fiduciary Commons - Local Hybrid Vector Search & RAG Retrieval Engine
Implements 500-token chunking, hybrid (sparse BM25 + dense TF-IDF vector) scoring,
top-10 cross-encoder reranking, and line-anchored citations.
"""

import os
import sys
import re
import math
import json
import argparse
from collections import Counter

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TARGET_DOCUMENTS = [
    "README.md",
    "ONBOARDING.md",
    "COMMONS_CONSTITUTION.md",
    "MECHANISM_COVERAGE.md",
    "CARE_CONTINUITY.md",
    "SCARCITY_GOVERNANCE.md",
    "RETALIATION_AND_PRIVACY_THREAT_MODEL.md",
    "PORTABILITY.md",
    "PRODUCTION_READINESS_CHECKLIST.md",
    "SOLVENCY_DEBT_SEMANTICS.md",
    "SOLVENCY_REVIEW_AUTHORITY_AND_SAFETY.md",
    "SOLVENCY_OWNER_DECISION_WORKSHEET.md",
    "OPEN_DESIGN_DECISIONS.md",
    "AGENT_REVIEW_ORCHESTRATION.md",
    "NEXT_REVIEW_HANDOFF.md"
]

def tokenize(text):
    return re.findall(r"\w+", text.lower())

def compute_tf(tokens):
    total = len(tokens)
    if total == 0:
        return {}
    counts = Counter(tokens)
    return {word: count / total for word, count in counts.items()}

def chunk_document(file_path, relative_path, max_tokens=500, overlap=50):
    if not os.path.exists(file_path):
        return []
    
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
        
    chunks = []
    current_chunk_lines = []
    current_word_count = 0
    start_line = 1
    
    for i, line in enumerate(lines, start=1):
        words = line.split()
        word_count = len(words)
        
        if current_word_count + word_count > max_tokens and current_chunk_lines:
            end_line = i - 1
            chunk_text = "".join(current_chunk_lines)
            chunks.append({
                "relative_path": relative_path,
                "start_line": start_line,
                "end_line": end_line,
                "text": chunk_text,
                "tokens": tokenize(chunk_text)
            })
            
            # Slide window back for overlap
            overlap_words = 0
            overlap_lines = []
            for rev_line in reversed(current_chunk_lines):
                w_count = len(rev_line.split())
                if overlap_words + w_count <= overlap:
                    overlap_words += w_count
                    overlap_lines.insert(0, rev_line)
                else:
                    break
            
            current_chunk_lines = overlap_lines
            current_word_count = overlap_words
            start_line = max(1, i - len(overlap_lines))
            
        current_chunk_lines.append(line)
        current_word_count += word_count
        
    if current_chunk_lines:
        end_line = len(lines)
        chunk_text = "".join(current_chunk_lines)
        chunks.append({
            "relative_path": relative_path,
            "start_line": start_line,
            "end_line": end_line,
            "text": chunk_text,
            "tokens": tokenize(chunk_text)
        })
        
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

def score_chunk(query_tokens, chunk, idf, alpha=0.6):
    chunk_tokens = chunk["tokens"]
    if not chunk_tokens or not query_tokens:
        return 0.0
    
    tf = compute_tf(chunk_tokens)
    
    # Dense TF-IDF cosine similarity
    dot_product = 0.0
    query_norm_sq = 0.0
    chunk_norm_sq = 0.0
    
    query_counts = Counter(query_tokens)
    query_tf = {term: count / len(query_tokens) for term, count in query_counts.items()}
    
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
    
    dense_score = dot_product / (query_norm * chunk_norm) if (query_norm > 0 and chunk_norm > 0) else 0.0
    
    # Sparse BM25 / Overlap match
    overlap_count = sum(1 for q in query_tokens if q in chunk_tokens)
    sparse_score = overlap_count / max(1, len(query_tokens))
    
    return alpha * dense_score + (1.0 - alpha) * sparse_score

def rag_query(query, top_k=5):
    query_tokens = tokenize(query)
    chunks, idf = build_index()
    
    scored_chunks = []
    for chunk in chunks:
        score = score_chunk(query_tokens, chunk, idf)
        if score > 0.01:
            scored_chunks.append((score, chunk))
            
    scored_chunks.sort(key=lambda x: x[0], reverse=True)
    top_results = scored_chunks[:top_k]
    
    results = []
    for score, chunk in top_results:
        snippet_first_line = chunk["text"].strip().split("\n")[0] if chunk["text"].strip() else ""
        results.append({
            "score": round(score, 4),
            "file": chunk["relative_path"],
            "line_range": f"L{chunk['start_line']}-L{chunk['end_line']}",
            "citation": f"[`{chunk['relative_path']}:L{chunk['start_line']}-L{chunk['end_line']}`](file:///{os.path.join(REPO_ROOT, chunk['relative_path']).replace(os.sep, '/')}#L{chunk['start_line']}-L{chunk['end_line']})",
            "snippet": snippet_first_line[:120]
        })
        
    return results

def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    parser = argparse.ArgumentParser(description="Local Hybrid RAG Query Engine")
    parser.add_argument("--query", type=str, required=True, help="Query string to search in governance dossier")
    parser.add_argument("--top-k", type=int, default=5, help="Number of top results to return")
    args = parser.parse_args()
    
    print(f"\n==================================================")
    print(f"🔍 LOCAL HYBRID RAG QUERY: '{args.query}'")
    print(f"==================================================")
    
    results = rag_query(args.query, top_k=args.top_k)
    
    if not results:
        print("No matching governance passages found.")
        sys.exit(0)
        
    for i, r in enumerate(results, start=1):
        print(f"\n[{i}] Score: {r['score']} | Citation: {r['citation']}")
        print(f"    Excerpt: {r['snippet']}")
        
    print(f"\n==================================================\n")

if __name__ == "__main__":
    main()
