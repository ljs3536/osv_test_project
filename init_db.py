import sqlite3
import os
import json
import yaml

# 데이터베이스 설정
DB_NAME = "osv_cache.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # 테이블 생성: 패키지명, 생태계, 취약점 데이터(JSON), 업데이트 시간
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS osv_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ecosystem TEXT,
            package_name TEXT,
            vuln_data TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # 인덱스 생성: 패키지명과 생태계로 검색할 때 속도 비약적 향상
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_pkg_eco ON osv_data(package_name, ecosystem)')
    conn.commit()
    return conn

def import_data_to_db(conn, ecosystem, folder_path):
    cursor = conn.cursor()
    print(f"[*] {ecosystem} 데이터 DB 삽입 중...")
    
    for root, _, files in os.walk(folder_path):
        for file in files:
            filepath = os.path.join(root, file)
            data = None
            try:
                if file.endswith(".json"):
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                elif file.endswith((".yaml", ".yml")):
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = yaml.safe_load(f)
                print(f"[*] {data} 데이터 DB 삽입 중...")
                if data and "affected" in data:
                    for affected in data.get("affected", []):
                        pkg_name = affected.get("package", {}).get("name")
                        if pkg_name:
                            cursor.execute(
                                "INSERT INTO osv_data (ecosystem, package_name, vuln_data) VALUES (?, ?, ?)",
                                (ecosystem, pkg_name, json.dumps(data))
                            )
            except Exception:
                continue
    conn.commit()
    print(f"[+] {ecosystem} DB 적재 완료!")

if __name__ == "__main__":
    conn = init_db()
    import_data_to_db(conn, "npm", "./npm")
    import_data_to_db(conn, "maven", "./maven")
    import_data_to_db(conn, "pypi", "./pypi")
    conn.close()