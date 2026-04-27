import xml.etree.ElementTree as ET
import os
import re


def generate_sqli_final_v2(xml_dir, output_path):
    dir_name = os.path.dirname(output_path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)

    boundary_file = os.path.join(xml_dir, 'boundaries.xml')
    if not os.path.exists(boundary_file):
        print(f"[-] {boundary_file}를 찾을 수 없습니다.")
        return

    # 1. Boundaries 로드 및 정리
    boundaries = []
    try:
        b_tree = ET.parse(boundary_file)
        for b in b_tree.findall('boundary'):
            # 접두사/접미사의 줄바꿈 및 불필요한 공백 제거
            pre = b.find('prefix').text if b.find('prefix') is not None else ""
            suf = b.find('suffix').text if b.find('suffix') is not None else ""

            boundaries.append({
                "pre": pre.strip() if pre else "",
                "suf": suf.strip() if suf else "",
                "clause": set(b.find('clause').text.split(",")) if b.find('clause') is not None else set(),
                "where": set(b.find('where').text.split(",")) if b.find('where') is not None else set()
            })
    except Exception as e:
        print(f"[!] {boundary_file} 처리 중 오류: {e}")
        return

    xml_files = ['boolean_blind.xml', 'error_based.xml', 'inline_query.xml',
                 'stacked_queries.xml', 'time_blind.xml', 'union_query.xml']

    final_payloads = set()

    for xml_filename in xml_files:
        xml_path = os.path.join(xml_dir, xml_filename)
        if not os.path.exists(xml_path): continue

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            attack_type = f"SQLi-{xml_filename.split('.')[0]}"

            for test in root.findall('.//test'):
                payload_text = test.find('.//payload').text
                if not payload_text: continue

                #XML 내부의 줄바꿈 및 연속된 공백을 하나의 공백으로 치환
                payload_text = re.sub(r'\s+', ' ', payload_text).strip()

                # DBMS 정보 가져오기
                dbms_list = []
                dbms_node = test.find('.//details/dbms')
                if dbms_node is not None and dbms_node.text:
                    dbms_list = [d.strip() for d in dbms_node.text.split(',')]
                else:
                    dbms_list = ['Generic']

                risk_val = test.find('risk').text if test.find('risk') is not None else "1"
                severity = {"3": "High", "2": "Medium"}.get(risk_val, "Low")

                t_clause = set(test.find('clause').text.split(",")) if test.find('clause') is not None else {"1"}
                t_where = set(test.find('where').text.split(",")) if test.find('where') is not None else {"1"}

                for b in boundaries:
                    if (b['clause'] & t_clause) and (b['where'] & t_where):
                        # 페이로드와 접두사/접미사 사이에 공백이 없으면 구문 에러가 날 수 있으므로 공백을 하나 추가해서 결합
                        pre = b['pre']
                        suf = b['suf']

                        combined = f"{pre} {payload_text} {suf}".strip()
                        combined = re.sub(r'\s+', ' ', combined)  # 중복 공백 제거

                        # 플레이스홀더 치환
                        combined = combined.replace("[GENERIC_SQL_COMMENT]", "-- ")
                        combined = combined.replace("[SLEEPTIME]", "5")
                        combined = combined.replace("[ORIGINAL]", "1")
                        combined = combined.replace("[DELIMITER_START]", "[START_M]")
                        combined = combined.replace("[DELIMITER_STOP]", "[STOP_M]")

                        # [RANDNUM], [RANDSTR] 처리
                        combined = combined.replace("[RANDSTR]", "vun")
                        combined = combined.replace("[RANDNUM]", "1")
                        for i in range(1, 10):
                            combined = combined.replace(f"[RANDSTR{i}]", f"vun{i}")
                            combined = combined.replace(f"[RANDNUM{i}]", f"{i}")

                        for target_db in dbms_list:
                            # 구분자를 '||' 대신 ':::'로 변경하여 페이로드 내부의 ||와 혼선 방지
                            line = f"{combined}::: {attack_type}::: {severity}::: {target_db}"
                            final_payloads.add(line)

        except Exception as e:
            print(f"[!] {xml_filename} 처리 중 오류: {e}")

    # 3. 최종 파일 저장
    with open(output_path, 'w', encoding='utf-8') as f:
        # 가나다순 정렬 및 빈 라인 방지
        for item in sorted(list(final_payloads)):
            if item.strip():
                f.write(item + "\n")

    print(f"[*] 추출 완료: {output_path} (총 {len(final_payloads)}개)")


if __name__ == "__main__":
    generate_sqli_final_v2(xml_dir='.', output_path='sqli_final_v2.txt')