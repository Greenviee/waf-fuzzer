import xml.etree.ElementTree as ET
import os


def generate_sqli_final(xml_dir, output_path):

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    boundary_file = os.path.join(xml_dir, 'boundaries.xml')
    if not os.path.exists(boundary_file):
        print(f"[-] {boundary_file}를 찾을 수 없습니다.")
        return

    # 1. Boundaries 데이터 로드 및 객체화
    boundaries = []
    try:
        b_tree = ET.parse(boundary_file)
        for b in b_tree.findall('boundary'):
            boundaries.append({
                "pre": b.find('prefix').text if b.find('prefix') is not None else "",
                "suf": b.find('suffix').text if b.find('suffix') is not None else "",
                "clause": set(b.find('clause').text.split(",")) if b.find('clause') is not None else set(),
                "where": set(b.find('where').text.split(",")) if b.find('where') is not None else set()
            })
    except Exception as e:
        print(f"[!] {boundary_file} 처리 중 오류: {e}")
        return

    # 2. 결합할 공격 기법 XML 파일 리스트
    xml_files = [
        'boolean_blind.xml',
        'error_based.xml',
        'inline_query.xml',
        'stacked_queries.xml',
        'time_blind.xml',
        'union_query.xml'
    ]

    final_payloads = set()
    total_count = 0

    for xml_filename in xml_files:
        xml_path = os.path.join(xml_dir, xml_filename)
        if not os.path.exists(xml_path):
            print(f"[-] 파일을 찾을 수 없습니다: {xml_path}")
            continue

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            attack_type = f"SQLi-{xml_filename.split('.')[0]}"

            for test in root.findall('.//test'):
                payload_text = test.find('.//payload').text
                if not payload_text: continue

                risk_val = test.find('risk').text if test.find('risk') is not None else "1"

                if risk_val == "3":
                    severity = "High"
                elif risk_val == "2":
                    severity = "Medium"
                else:
                    severity = "Low"

                t_clause = set(test.find('clause').text.split(",")) if test.find('clause') is not None else set(["1"])
                t_where = set(test.find('where').text.split(",")) if test.find('where') is not None else set(["1"])

                # Boundary와 매칭
                for b in boundaries:
                    if (b['clause'] & t_clause) and (b['where'] & t_where):
                        pre = b['pre'] if b['pre'] is not None else ""
                        suf = b['suf'] if b['suf'] is not None else ""
                        combined = f"{pre}{payload_text}{suf}"

                        # 플레이스홀더 치환 (동일)
                        combined = combined.replace("[GENERIC_SQL_COMMENT]", "-- ")
                        combined = combined.replace("[RANDSTR]", "vun")
                        combined = combined.replace("[RANDNUM]", "1")
                        combined = combined.replace("[RANDSTR1]", "vun1")
                        combined = combined.replace("[RANDSTR2]", "vun2")
                        combined = combined.replace("[SLEEPTIME]", "5")
                        combined = combined.replace("[ORIGINAL]", "1")
                        combined = combined.replace("[DELIMITER_START]", "").replace("[DELIMITER_STOP]", "")

                        # risk 대신 severity 정보를 포함하여 저장
                        line = f"{combined.strip()}||{attack_type}||{severity}"
                        final_payloads.add(line)

            print(f"[+] {xml_filename} 매칭 완료")
        except Exception as e:
            print(f"[!] {xml_filename} 처리 중 오류: {e}")

    # 3. 최종 파일 저장
    with open(output_path, 'w', encoding='utf-8') as f:
        # 가나다순 정렬하여 저장
        for item in sorted(list(final_payloads)):
            f.write(item + "\n")

    print(f"\n[*] 최종 유의미한 조합 {len(final_payloads)}개 추출 완료: {output_path}")


# 실행 부분
# xml_dir: XML 파일들이 있는 경로 (현재 디렉토리라면 '.')
# output_path: 최종 저장될 경로
generate_sqli_final(xml_dir='.', output_path='config/payloads/sqli_final_2.txt')