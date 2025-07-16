#!/usr/bin/env python3
import json
import time
import requests

BASE_URL = "http://localhost:8989"
INPUT_FILE = "input.json"
OUTPUT_FILE = "output.json"

def test_endpoint(query):
    """Test a single endpoint"""
    print(f"\n{'='*50}")
    print(f"Testing: {query}")
    print(f"{'='*50}")

    payload = {"query": query}

    try:
        response = requests.post(
            f"{BASE_URL}/analysis_agent",
            json=payload,
            timeout=30
        )

        if response.status_code == 200:
            result = response.json()
            return {
                "query": query,
                "analysis": result.get("analysis", ""),
                "result": result.get("result", "UNKNOWN")
            }
        else:
            return {
                "query": query,
                "analysis": f"Lỗi HTTP {response.status_code}: {response.text}",
                "result": "UNKNOWN"
            }

    except requests.exceptions.RequestException as e:
        return {
            "query": query,
            "analysis": f"Lỗi khi gửi request: {str(e)}",
            "result": "UNKNOWN"
        }

def test_health():
    """Test health endpoint"""
    print("\nTesting Health Endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        if response.status_code == 200:
            print("Health check passed")
            print(f"Response: {response.json()}")
        else:
            print(f"Health check failed: {response.status_code}")
    except Exception as e:  # Catch-all for unexpected errors
        print(f"Health check error: {e}")

def main():
    print("Security Analysis Agent Test Suite")
    print("=" * 50)

    # Test health first
    test_health()

    # Load input
    try:
        with open(INPUT_FILE, "r", encoding="utf-8") as f:
            input_queries = json.load(f)
    except Exception as e:
        print(f"Lỗi khi đọc {INPUT_FILE}: {e}")
        return

    results = []

    for i, item in enumerate(input_queries, 1):
        query = item.get("query", "")
        print(f"[{i}] Analysis: {query}")
        result = test_endpoint(query)
        results.append(result)
        print(f"Result: {result['result']}")
        time.sleep(2)  # Tránh rate-limit nếu cần

    # Run tests
    # Save output
    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\nSaved output: {OUTPUT_FILE}")
    except Exception as e:
        print(f"Error saving output file: {e}")

    print(f"\n{'='*50}")
    print("Test Suite Completed")
    print(f"{'='*50}")

if __name__ == "__main__":
    main()
