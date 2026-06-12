import os
import glob
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

# [신규] 버전 비교 유틸리티 (1.10.0 > 1.2.0 을 처리하기 위해 리스트로 변환)
def _parse_version_string(v_str):
    # 정규식을 써서 숫자 부분만 추출하여 리스트로 만듭니다. (예: "1.2.3" -> [1, 2, 3])
    parts = re.findall(r'\d+', str(v_str))
    return [int(x) for x in parts]

# [신규] 오프라인 스캐닝 핵심 엔진
def _scan_offline_local(packages, ecosystem_folder):
    """
    로컬 폴더(npm, maven 등)의 모든 JSON 파일을 읽어 
    패키지 이름과 버전을 수학적으로 비교하여 매칭합니다.
    """
    if not os.path.exists(ecosystem_folder):
        print(f"[!] 로컬 데이터 폴더가 없습니다: {ecosystem_folder}")
        return []

    # 로컬 JSON 파일 목록 가져오기
    json_files = glob.glob(os.path.join(ecosystem_folder, "*.json"))
    
    findings = {pkg["name"]: {"version": pkg["version"], "vulns": []} for pkg in packages}
    package_names = set(findings.keys())

    for filepath in json_files:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                vuln_data = json.load(f)
        except Exception:
            continue

        vuln_id = vuln_data.get("id", "Unknown")
        aliases = vuln_data.get("aliases", [])
        summary = vuln_data.get("summary", vuln_data.get("details", "요약 없음"))

        for affected in vuln_data.get("affected", []):
            pkg_name = affected.get("package", {}).get("name")
            if pkg_name not in package_names:
                continue

            # 패키지 이름이 일치하면, 버전이 취약 범위(ranges)에 들어가는지 검사
            target_v_str = findings[pkg_name]["version"]
            target_v = _parse_version_string(target_v_str)
            is_vulnerable = False

            # 1. Exact version match 확인
            if target_v_str in affected.get("versions", []):
                is_vulnerable = True

            # 2. Ranges (introduced ~ fixed) 확인
            for r in affected.get("ranges", []):
                if is_vulnerable: break
                
                introduced = None
                fixed = None
                
                for event in r.get("events", []):
                    if "introduced" in event:
                        introduced = _parse_version_string(event["introduced"] if event["introduced"] != "0" else "0.0.0")
                    if "fixed" in event:
                        fixed = _parse_version_string(event["fixed"])

                if introduced and not fixed:
                    if target_v >= introduced:
                        is_vulnerable = True
                elif introduced and fixed:
                    if target_v >= introduced and target_v < fixed:
                        is_vulnerable = True

            # 취약점으로 판별되면 결과 리스트에 추가
            if is_vulnerable:
                findings[pkg_name]["vulns"].append({
                    "id": vuln_id,
                    "aliases": aliases,
                    "summary": summary[:200] + "..." if len(summary) > 200 else summary # 너무 길면 자름
                })

    # 프론트엔드 포맷으로 변환
    results = []
    for pkg_name, data in findings.items():
        results.append({
            "packageName": pkg_name,
            "version": data["version"],
            "vulns": data["vulns"]
        })
    return results

@app.post("/api/analyze")
async def analyze_file(
    file: UploadFile = File(...),
    ecosystem: str = Form(...),
    mode: str = Form("online") # 기본값은 online, 프론트에서 offline 전달 가능
):
    content = await file.read()
    text_content = content.decode('utf-8', errors='ignore')
    
    packages = []
    osv_ecosystem = ""
    
    if ecosystem == "pypi":
        packages = parse_requirements(text_content) # 기존에 작성하신 함수
        osv_ecosystem = "PyPI"
    elif ecosystem == "npm":
        packages = parse_package_json(text_content) # 기존에 작성하신 함수
        osv_ecosystem = "npm"
    elif ecosystem == "maven":
        packages = parse_pom_xml(text_content)      # 기존에 작성하신 함수
        osv_ecosystem = "Maven"
        
    if not packages:
        return {"results": []}

    # ==========================================
    # [분기점] 오프라인 모드 vs 온라인 모드
    # ==========================================
    if mode == "offline":
        print(f"[*] 오프라인 로컬 스캔 시작 ({ecosystem} 폴더 대상)")
        # ecosystem과 동일한 이름의 로컬 폴더(npm, maven)를 뒤집니다.
        final_response = await asyncio.to_thread(_scan_offline_local, packages, ecosystem)
        return {"results": final_response}
    
    else:
        print("[*] 온라인 API 스캔 시작")
        payload = {
            "queries": [
                {"package": {"name": p["name"], "ecosystem": osv_ecosystem}, "version": p["version"]}
                for p in packages
            ]
        }
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