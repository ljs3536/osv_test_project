from fastapi import FastAPI, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
import xml.etree.ElementTree as ET
import asyncio
import json
import urllib.request
import re

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- (이전과 동일한 _query_osv_batch, _query_osv_vuln_detail, _fetch_all_details 함수 유지) ---
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
# -----------------------------------------------------------------------------------------

# 파서 1: Python (requirements.txt)
def parse_requirements(content: str):
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'): continue
        match = re.match(r'^([A-Za-z0-9_\.-]+)==([A-Za-z0-9\.]+)$', line)
        if match:
            packages.append({"name": match.group(1), "version": match.group(2)})
    return packages

# 파서 2: NPM (package.json)
def parse_package_json(content: str):
    packages = []
    try:
        data = json.loads(content)
        # dependencies와 devDependencies 모두 탐색
        for section in ["dependencies", "devDependencies"]:
            for name, version in data.get(section, {}).items():
                # npm 버전 표기법(^, ~, >, <) 제거하고 순수 버전만 추출
                clean_version = re.sub(r'^[~^><= ]+', '', version)
                packages.append({"name": name, "version": clean_version})
    except json.JSONDecodeError:
        pass
    return packages

# 파서 3: Java Maven (pom.xml)
def parse_pom_xml(content: str):
    packages = []
    try:
        # 네임스페이스 문제 우회 (단순화를 위해)
        content = re.sub(r'\sxmlns="[^"]+"', '', content, count=1)
        root = ET.fromstring(content)
        for dep in root.findall(".//dependency"):
            group_id = dep.findtext("groupId")
            artifact_id = dep.findtext("artifactId")
            version = dep.findtext("version")
            # OSV API는 Maven 패키지를 "groupId:artifactId" 형태로 요구합니다.
            if group_id and artifact_id and version and not version.startswith("${"):
                packages.append({"name": f"{group_id}:{artifact_id}", "version": version})
    except Exception as e:
        print(f"POM 파싱 에러: {e}")
    return packages

@app.post("/api/analyze")
async def analyze_file(
    file: UploadFile = File(...),
    ecosystem: str = Form(...)  # 프론트에서 넘어오는 생태계 정보 (pypi, npm, maven)
):
    content = await file.read()
    text_content = content.decode('utf-8', errors='ignore')
    
    # 생태계에 따른 파서 라우팅
    packages = []
    osv_ecosystem = ""
    
    if ecosystem == "pypi":
        packages = parse_requirements(text_content)
        osv_ecosystem = "PyPI"
    elif ecosystem == "npm":
        packages = parse_package_json(text_content)
        osv_ecosystem = "npm"
    elif ecosystem == "maven":
        packages = parse_pom_xml(text_content)
        osv_ecosystem = "Maven"
        
    if not packages:
        return {"results": []}

    # OSV Batch API 페이로드 구성
    payload = {
        "queries": [
            {"package": {"name": p["name"], "ecosystem": osv_ecosystem}, "version": p["version"]}
            for p in packages
        ]
    }

    # API 호출 로직은 기존과 동일
    batch_resp = await asyncio.to_thread(_query_osv_batch, payload)
    raw_results = batch_resp.get("results", [])

    unique_vuln_ids = {vuln["id"] for res in raw_results for vuln in res.get("vulns", [])}
    details_map = await _fetch_all_details(list(unique_vuln_ids))

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