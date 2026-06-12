import json
import urllib.request
import urllib.error
import asyncio
from typing import Dict, Any, List

# 1. Batch API 호출 (취약점 ID 확보)
def _query_osv_batch(payload: Dict[str, Any]) -> Dict[str, Any]:
    endpoint = "https://api.osv.dev/v1/querybatch"
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(endpoint, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10.0) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception as e:
        print(f"[!] Batch API 에러: {e}")
        return {"results": []}

# 2. 개별 취약점 상세 정보 호출 (Summary, Details 확보)
def _query_osv_vuln_detail(vuln_id: str) -> Dict[str, Any]:
    endpoint = f"https://api.osv.dev/v1/vulns/{vuln_id}"
    request = urllib.request.Request(endpoint, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=5.0) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception:
        return {"id": vuln_id, "summary": "상세 정보 조회 실패"}

async def _fetch_all_details(vuln_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    # 비동기로 여러 ID의 상세 정보를 동시에 가져옵니다 (속도 최적화)
    loop = asyncio.get_running_loop()
    tasks = [loop.run_in_executor(None, _query_osv_vuln_detail, vid) for vid in vuln_ids]
    results = await asyncio.gather(*tasks)
    return {res["id"]: res for res in results if "id" in res}

async def main():
    test_payload = {
        "queries": [
            {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.20.0"},
            {"package": {"name": "jinja2", "ecosystem": "PyPI"}, "version": "2.10.0"}
        ]
    }

    print("[*] 1단계: OSV Batch API 호출 중...")
    batch_response = await asyncio.to_thread(_query_osv_batch, test_payload)
    results = batch_response.get("results", [])

    # 중복을 제거하여 조회할 ID 목록 수집
    unique_vuln_ids = set()
    for res in results:
        for vuln in res.get("vulns", []):
            unique_vuln_ids.add(vuln["id"])

    print(f"[*] 2단계: 발견된 취약점 {len(unique_vuln_ids)}개의 상세 정보 Fetch 중...")
    details_map = await _fetch_all_details(list(unique_vuln_ids))

    print("\n[+] 최종 결과 출력!\n")
    for i, result in enumerate(results):
        target_pkg = test_payload["queries"][i]["package"]["name"]
        vulns = result.get("vulns", [])
        
        print(f"[{target_pkg}] -> 발견된 취약점: {len(vulns)}개")
        if vulns:
            first_vuln_id = vulns[0]["id"]
            detail = details_map.get(first_vuln_id, {})
            summary = detail.get("summary", "요약 정보 없음")
            aliases = detail.get("aliases", [])
            
            print(f"    - 대표 취약점 ID: {first_vuln_id}")
            print(f"    - 다른 이름(CVE 등): {', '.join(aliases) if aliases else '없음'}")
            print(f"    - 내용 요약: {summary}")
        print("-" * 50)

if __name__ == "__main__":
    asyncio.run(main())