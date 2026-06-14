import os
import glob
from fastapi import FastAPI, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import xml.etree.ElementTree as ET
import asyncio
import json
import urllib.request
import re
import yaml
import sqlite3
# # 전역 캐시 딕셔너리
# OSV_CACHE = {
#     "pypi": {},
#     "npm": {},
#     "maven": {}
# }

# def load_offline_data(ecosystem: str, folder_path: str):
#     """
#     폴더 구조나 확장자(JSON/YAML)에 상관없이 OSV 데이터를 읽어 캐시에 적재합니다.
#     """
#     if not os.path.exists(folder_path):
#         print(f"[!] 폴더를 찾을 수 없습니다: {folder_path}")
#         return

#     print(f"[*] {ecosystem} 오프라인 데이터 메모리 적재 시작... ({folder_path})")
    
#     file_count = 0
#     for root, dirs, files in os.walk(folder_path):
#         for file in files:
#             filepath = os.path.join(root, file)
#             data = None
#             try:
#                 if file.endswith(".json"):
#                     with open(filepath, 'r', encoding='utf-8') as f:
#                         data = json.load(f)
#                 elif file.endswith((".yaml", ".yml")):
#                     with open(filepath, 'r', encoding='utf-8') as f:
#                         data = yaml.safe_load(f)
#             except Exception:
#                 continue

#             if not data:
#                 continue

#             file_count += 1
#             # 패키지 이름을 추출하여 캐시에 딕셔너리 형태로 분류합니다.
#             for affected in data.get("affected", []):
#                 pkg_name = affected.get("package", {}).get("name")
#                 if pkg_name:
#                     if pkg_name not in OSV_CACHE[ecosystem]:
#                         OSV_CACHE[ecosystem][pkg_name] = []
#                     OSV_CACHE[ecosystem][pkg_name].append(data)

#     print(f"[+] {ecosystem} 메모리 적재 완료! (읽은 파일: {file_count}개, 고유 패키지: {len(OSV_CACHE[ecosystem])}개)")
# # FastAPI Lifespan (서버 켜질 때 딱 한 번 실행)
# @asynccontextmanager
# async def lifespan(app: FastAPI):
#     # npm, maven 폴더의 데이터를 캐시에 로드 (폴더 경로는 실제에 맞게 수정)
#     load_offline_data("npm", "./npm")
#     load_offline_data("maven", "./maven")
#     load_offline_data("pypi", "./pypi")
#     yield
#     # 서버 종료 시 처리할 로직 (필요시)

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

# main.py에서 수정할 부분
def get_vulns_from_db(ecosystem, pkg_name):
    conn = sqlite3.connect("osv_cache.db")
    cursor = conn.cursor()
    # 쿼리 실행
    cursor.execute(
        "SELECT vuln_data FROM osv_data WHERE ecosystem = ? AND package_name = ?",
        (ecosystem, pkg_name)
    )
    rows = cursor.fetchall()
    conn.close()
    
    # DB에서 가져온 JSON 문자열을 리스트로 변환
    return [json.loads(row[0]) for row in rows]

def get_vulns_from_db(ecosystem, pkg_name):
    conn = sqlite3.connect("osv_cache.db")
    cursor = conn.cursor()
    # 쿼리 실행
    cursor.execute(
        "SELECT vuln_data FROM osv_data WHERE ecosystem = ? AND package_name = ?",
        (ecosystem, pkg_name)
    )
    rows = cursor.fetchall()
    conn.close()
    
    # DB에서 가져온 JSON 문자열을 리스트로 변환
    return [json.loads(row[0]) for row in rows]

# 오프라인 스캐닝 핵심 엔진
def _scan_offline_local(packages, ecosystem: str):
    """
    메모리(OSV_CACHE)에 적재된 데이터를 사용하여
    패키지 이름과 버전을 초고속으로 수학적 비교 매칭합니다.
    """
    findings = {pkg["name"]: {"version": pkg["version"], "vulns": []} for pkg in packages}


    # 사용자가 업로드한 패키지들만 순회합니다. (전체 파일을 뒤질 필요가 없음!)
    for pkg in packages:
        pkg_name = pkg["name"]
        target_v_str = pkg["version"]
        target_v = _parse_version_string(target_v_str)

        # 🚀 여기서 O(1) 속도로 캐시에서 취약점 목록을 낚아챕니다.
        cached_vulns = get_vulns_from_db(ecosystem, pkg_name)

        # 캐시에 패키지가 없으면 취약점이 없는 것이므로 패스
        if not cached_vulns:
            continue

        for vuln_data in cached_vulns:
            vuln_id = vuln_data.get("id", "Unknown")
            aliases = vuln_data.get("aliases", [])
            summary = vuln_data.get("summary", vuln_data.get("details", "요약 없음"))

            for affected in vuln_data.get("affected", []):
                # 캐시에서 가져왔으므로 이름 비교는 생략 가능하지만 2중 안전장치로 유지
                if affected.get("package", {}).get("name") != pkg_name:
                    continue

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
                        "summary": summary[:200] + "..." if len(summary) > 200 else summary
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