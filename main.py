# main.py
from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import json
import urllib.request
import re

app = FastAPI()

# 1. CORS 설정 (Next.js의 접근 허용)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # 프론트엔드 주소
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- (이전에 만든 OSV API 통신 함수들) ---
def _query_osv_batch(payload):
    endpoint = "https://api.osv.dev/v1/querybatch"
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(endpoint, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10.0) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception as e:
        print(f"[!] Batch API 에러: {e}")
        return {"results": []}

def _query_osv_vuln_detail(vuln_id: str):
    endpoint = f"https://api.osv.dev/v1/vulns/{vuln_id}"
    req = urllib.request.Request(endpoint, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5.0) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception:
        return {"id": vuln_id, "summary": "상세 정보 조회 실패"}

async def _fetch_all_details(vuln_ids):
    loop = asyncio.get_running_loop()
    tasks = [loop.run_in_executor(None, _query_osv_vuln_detail, vid) for vid in vuln_ids]
    results = await asyncio.gather(*tasks)
    return {res["id"]: res for res in results if "id" in res}
# ----------------------------------------

# 간단한 requirements.txt 파서 (테스트용)
def parse_requirements(content: str):
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'): continue
        # requests==2.20.0 형태만 추출
        match = re.match(r'^([A-Za-z0-9_\.-]+)==([A-Za-z0-9\.]+)$', line)
        if match:
            packages.append({"name": match.group(1), "version": match.group(2)})
    return packages

@app.post("/api/analyze")
async def analyze_file(file: UploadFile = File(...)):
    # 1. 파일 읽기 및 파싱
    content = await file.read()
    text_content = content.decode('utf-8', errors='ignore')
    
    packages = parse_requirements(text_content)
    if not packages:
        return {"results": []}

    # 2. OSV Batch API 페이로드 구성
    payload = {
        "queries": [
            {"package": {"name": p["name"], "ecosystem": "PyPI"}, "version": p["version"]}
            for p in packages
        ]
    }

    # 3. OSV API 호출 (Batch -> Details)
    batch_resp = await asyncio.to_thread(_query_osv_batch, payload)
    raw_results = batch_resp.get("results", [])

    unique_vuln_ids = {vuln["id"] for res in raw_results for vuln in res.get("vulns", [])}
    details_map = await _fetch_all_details(list(unique_vuln_ids))

    # 4. 프론트엔드 포맷으로 응답 데이터 재조립
    final_response = []
    for i, res in enumerate(raw_results):
        pkg = packages[i]
        vulns = res.get("vulns", [])
        
        formatted_vulns = []
        for v in vulns:
            vid = v["id"]
            detail = details_map.get(vid, {})
            formatted_vulns.append({
                "id": vid,
                "aliases": detail.get("aliases", []),
                "summary": detail.get("summary", "상세 요약 정보 없음")
            })
            
        final_response.append({
            "packageName": pkg["name"],
            "version": pkg["version"],
            "vulns": formatted_vulns
        })

    return {"results": final_response}