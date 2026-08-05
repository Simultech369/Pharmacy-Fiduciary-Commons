#!/usr/bin/env python3
import os
import sys
import subprocess

def run_command(args, check=True):
    try:
        result = subprocess.run(args, capture_output=True, text=True, check=check, encoding="utf-8")
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error running command {' '.join(args)}: {e.stderr}", file=sys.stderr)
        sys.exit(1)

def main():
    # Force UTF-8 encoding on stdout
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    script_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.dirname(script_dir)
    
    print("🔍 Running pre-commit AI guardrail audit...")
    
    # 1. Get cached files
    files_changed = run_command(["git", "diff", "--cached", "--name-only"])
    if not files_changed:
        print("✅ No staged changes found. Skipping audit.")
        sys.exit(0)
        
    print(f"Staged files for review:\n{files_changed}")
    
    # 2. Get the full cached diff
    diff_content = run_command(["git", "diff", "--cached"])
    if not diff_content.strip():
        print("✅ Staged diff is empty. Skipping audit.")
        sys.exit(0)
        
    # Create reviews dir if not exists
    reviews_dir = os.path.join(root_dir, "reviews")
    os.makedirs(reviews_dir, exist_ok=True)
    
    # Write diff to a temporary file
    temp_diff_path = os.path.join(reviews_dir, "temp-pre-commit-diff.txt")
    with open(temp_diff_path, "w", encoding="utf-8") as f:
        f.write(diff_content)
        
    print(f"Stored staged diff at {temp_diff_path}")
    
    # 3. Call openrouter_review.py
    approved_disclosure = os.environ.get("PBM_APPROVE_EXTERNAL_REVIEW") or os.environ.get("PBM_APPROVED_DISCLOSURE_CLASS")
    if approved_disclosure != "LOCAL_CODE_DIRTY":
        print("External pre-commit review is blocked until the operator explicitly approves LOCAL_CODE_DIRTY disclosure.")
        print("Set PBM_APPROVE_EXTERNAL_REVIEW=LOCAL_CODE_DIRTY only after confirming the staged diff may be sent externally.")
        if os.path.exists(temp_diff_path):
            os.remove(temp_diff_path)
        sys.exit(1)

    openrouter_script = os.path.join(script_dir, "openrouter_review.py")
    
    # Call using sys.executable to ensure we use the same python environment
    review_cmd = [
        sys.executable,
        openrouter_script,
        "--role", "guardrail",
        "--context", temp_diff_path,
        "--disclosure-class", "LOCAL_CODE_DIRTY",
        "--approve-disclosure", approved_disclosure
    ]
    
    print("🤖 Calling AI Auditor via OpenRouter...")
    try:
        # Run and stream stdout/stderr
        subprocess.run(review_cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ OpenRouter review script failed to execute successfully: {e}")
        # Clean up
        if os.path.exists(temp_diff_path):
            os.remove(temp_diff_path)
        sys.exit(1)
        
    # 4. Read the review output file
    review_output_path = os.path.join(reviews_dir, "guardrail-review.txt")
    if not os.path.exists(review_output_path):
        print(f"❌ Error: Expected review output file not found at {review_output_path}")
        if os.path.exists(temp_diff_path):
            os.remove(temp_diff_path)
        sys.exit(1)
        
    with open(review_output_path, "r", encoding="utf-8") as f:
        review_content = f.read()
        
    # Clean up temp diff
    if os.path.exists(temp_diff_path):
        os.remove(temp_diff_path)
        
    # 5. Check if the review returns FAIL
    # We look for "FAIL" case-sensitively or case-insensitively, but usually a strict "FAIL" is expected.
    # We will do case-insensitive search for safety, but highlight if FAIL is found.
    if "FAIL" in review_content:
        print("\n🛑 AI Guardrail Review: FAIL")
        print("Please resolve the issues listed in the review before committing.")
        sys.exit(1)
    elif "PASS" in review_content:
        print("\n✅ AI Guardrail Review: PASS")
        sys.exit(0)
    else:
        print("\n⚠️ AI Guardrail Review: No clear PASS or FAIL found. Defaulting to block for security.")
        sys.exit(1)

if __name__ == "__main__":
    main()
