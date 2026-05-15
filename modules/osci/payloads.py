import os
import re
import random
from dataclasses import dataclass
from typing import List, Dict, Any

@dataclass(frozen=True, slots=True)
class Payload:
    value: str
    attack_type: str
    risk_level: str
    target_os: str = "Unix"
    action_level: str = "SHELL"

def _resolve_payload_file() -> str | None:
    candidates = [os.path.join("config", "payloads", "osci", "osci.txt")]
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    return None

def _get_suffixes(p_is_windows, p_is_shell, p_is_php, p_attack_type, mode=None):
    if p_is_windows:
        if p_is_shell:
            # Windows CMD/PS suffix
            return ["", "\"", "&", "^", "|"]
        if p_is_php:
            # Windows PHP suffix
            return ["", ";", ";//", ";#"]
    else: # Unix
        if p_is_shell:
            if "in-band" in p_attack_type:
                return ["", "\"", "&", "'", "//", "\\", "\\\\", "|"]
            else: # time-based
                return ["", " \"", " #", " &", " '", " //", " \\\\", " |"]
        if p_is_php:
            if mode == 'dot':
                return [")}", ";#", ";.\"", ";.'", ";//", ";", ";\\\\"]
            else:
                return [";#", ";)}", ";.\"", ";.'", ";//", ";", ";\\\\"]
    return [""]

def get_osci_payloads() -> list[Payload]:
    file_path = _resolve_payload_file()
    if not file_path:
        return []

    intermediate_payloads = [] # Prefix 까지만 다중화
    
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or ":::" not in line:
                continue
            
            parts = [p.strip() for p in line.split(":::", 4)]
            if len(parts) < 5: continue
                
            skel_raw = parts[0]
            m_type, m_risk, m_os, m_level = parts[1], parts[2], parts[3], parts[4]

            # Prefix 다중화 로직
            prefix_set = [""]
            
            # Unix Prefix 로직
            if m_os == "Unix":
                if m_level == "PHP":
                    if skel_raw.startswith("${"): prefix_set = [""]
                    elif "}print" in skel_raw: prefix_set = ["\")", "')", ")"]
                    elif "print(" in skel_raw and "[CONCAT]print" not in skel_raw:
                        prefix_set = ["", "\")", "')", ")", "'"]
                    elif "[CONCAT]print" in skel_raw: prefix_set = ["", "\"", "'"]
                elif m_level == "SHELL COMMAND":
                    if not skel_raw.startswith("&"): prefix_set = ["", "\"", "'"]
                    else: prefix_set = [""]
            
            # Windows Prefix 로직
            elif m_os == "Windows":
                if m_level == "PHP":
                    if skel_raw.startswith("${"): 
                        prefix_set = [""]
                    elif "}print" in skel_raw: 
                        prefix_set = ["\")", "')", ")"]
                    elif "[CONCAT]print" in skel_raw or "print(" in skel_raw:
                        prefix_set = ["", "\")", "')", ")"]
                elif m_level in ("SHELL COMMAND (CMD)", "SHELL COMMAND (PS)"):
                    prefix_set = ["", "\"", "^"]

            for pre in prefix_set:
                val = skel_raw.replace("[PREFIX]", pre) if "[PREFIX]" in skel_raw else pre + skel_raw
                intermediate_payloads.append({
                    "payload": val,
                    "metadata": f"{m_type}:::{m_risk}:::{m_os}:::{m_level}"
                })

    # Concat 및 Suffix 다중화
    final_payload_objects = []
    
    for item in intermediate_payloads:
        payload = item["payload"]
        metadata = item["metadata"]
        m_parts = metadata.split(":::")
        m_os = m_parts[2]
        m_level = m_parts[3]
        attack_type = m_parts[0]
        
        is_unix    = (m_os == "Unix")
        is_windows = (m_os == "Windows")
        is_php     = (m_level == "PHP")
        is_shell   = (m_level == "SHELL COMMAND")
        is_cmd     = (m_level == "SHELL COMMAND (CMD)")
        is_ps      = (m_level == "SHELL COMMAND (PS)")

        if is_unix:
            if is_shell and "tr -d '[CONCAT]'" in payload:
                replacements = ["|", "|", "\n", "|", "||"]
                new_payload = payload
                for r in replacements:
                    new_payload = new_payload.replace("[CONCAT]", r, 1)
                for s in _get_suffixes(False, True, False, attack_type):
                    final_payload_objects.append(_finalize(new_payload.replace("[SUFFIX]", s), metadata))

            elif is_shell and re.match(r'^[\'"]?\[CONCAT\] sleep 0', payload):
                replacements = ["&", "&&", "&&", "&&", "&&"]
                new_payload = payload
                for r in replacements:
                    new_payload = new_payload.replace("[CONCAT]", r, 1)
                for s in _get_suffixes(False, True, False, attack_type):
                    final_payload_objects.append(_finalize(new_payload.replace("[SUFFIX]", s), metadata))

            elif is_shell:
                shell_delimiters = ["\n", "&&", "&", ";", "|", "||"]
                for d in shell_delimiters:
                    temp_payload = payload
                    if d == ";":
                        new_p = temp_payload.replace("[CONCAT]echo", ";echo").replace("[CONCAT]", "; ")
                    else:
                        new_p = temp_payload.replace("[CONCAT]", d)
                    
                    for s in _get_suffixes(False, True, False, attack_type):
                        final_payload_objects.append(_finalize(new_p.replace("[SUFFIX]", s), metadata))

            elif is_php:
                for mode in ['nl', 'semi', 'dot']:
                    if mode == 'nl':
                        p = payload.replace(")[CONCAT]}", ");}").replace("[CONCAT]print", ".print").replace("[CONCAT]echo", "\necho")
                    elif mode == 'semi':
                        p = payload.replace(")[CONCAT]}", ");}").replace("[CONCAT]print", ".print").replace("[CONCAT]echo", ";echo")
                    else:
                        p = payload.replace(")[CONCAT]}", ");}").replace("[CONCAT]print", ".print").replace("[CONCAT]echo", "`.`echo")
                    
                    for s in _get_suffixes(False, False, True, attack_type, mode):
                        final_payload_objects.append(_finalize(p.replace("[SUFFIX]", s), metadata))
        
        elif is_windows:
            if is_cmd:
                shell_delimiters = ["&", "&&", "|", "||", "\r\n"]
                
                for d in shell_delimiters:
                    new_p = payload
                    
                    if d == "&":
                        new_p = new_p.replace("[CONCAT]echo", " & echo")
                        new_p = new_p.replace("[CONCAT]set", " & set")
                        new_p = new_p.replace("[CONCAT]call", " & call")
                        new_p = new_p.replace("[CONCAT]if", " & if")
                        new_p = new_p.replace("[CONCAT]cmd", " & cmd")
                        new_p = new_p.replace("[CONCAT]timeout", " & timeout")
                        new_p = new_p.replace("[CONCAT]ping", " & ping")

                    new_p = new_p.replace("[CONCAT]", d)
                    
                    for s in _get_suffixes(True, True, False, attack_type):
                        final_payload_objects.append(_finalize(new_p.replace("[SUFFIX]", s), metadata))

            elif is_ps:
                shell_delimiters = [";", "&", "&&", "|", "||"]
                
                for d in shell_delimiters:
                    new_p = payload.replace("[CONCAT]", d)
                    
                    for s in _get_suffixes(True, True, False, attack_type):
                        final_payload_objects.append(_finalize(new_p.replace("[SUFFIX]", s), metadata))

            elif is_php:
                php_delimiters = [";", "\n"]
                
                for d in php_delimiters:
                    new_p = payload

                    if ")[CONCAT]}" in new_p:
                        new_p = new_p.replace(")[CONCAT]}", ");}")
                    
                    if d == ";":
                        new_p = new_p.replace("[CONCAT]echo", " & echo")
                        new_p = new_p.replace("[CONCAT]set", " & set")
                        new_p = new_p.replace("[CONCAT]call", " & call")
                    elif d == "\n":
                        new_p = new_p.replace("[CONCAT]echo", "\necho")
                        new_p = new_p.replace("[CONCAT]set", "\nset")
                        new_p = new_p.replace("[CONCAT]call", "\ncall")
                    
                    new_p = new_p.replace("[CONCAT]print", f"{d}print")
                    
                    new_p = new_p.replace("[CONCAT]", d)
                    
                    for s in _get_suffixes(True, False, True, attack_type):
                        final_payload_objects.append(_finalize(new_p.replace("[SUFFIX]", s), metadata))
        
    return final_payload_objects

MARKER = "SVSDAAAA"
MARKER_LEN = len(MARKER)          # 8
MARKER_LEN_WC = MARKER_LEN + 1    # 9 (wc -c는 개행 포함)

def _finalize(val: str, metadata: str) -> Payload:
    m_parts = metadata.split(":::")
    target_os = m_parts[2]
    action_level = m_parts[3]
    
    n1 = random.randint(10, 99)
    n2 = 100 - n1

    res = val.replace("[MARKER]", MARKER)
    res = res.replace("[N1]", str(n1)).replace("[N2]", str(n2))

    # [N] 치환 로직 (기존 유지)
    wc_pattern = r"wc -c.*\[N\]|\[N\].*wc -c"
    marker_len_patterns = [r"-ne \[N\]", r"-eq \[N\]", r"\.Length -ne \[N\]", r"\.Length -eq \[N\]", r"==\[N\]", r"== \[N\]"]
    ping_pattern = r"ping -n \[N\]"

    if re.search(wc_pattern, val):
        res = res.replace("[N]", str(MARKER_LEN_WC))
    elif re.search(ping_pattern, val):
        res = res.replace("[N]", "5")
    elif any(re.search(p, val) for p in marker_len_patterns):
        res = res.replace("[N]", str(MARKER_LEN))
    else:
        res = res.replace("[N]", str(n1 + n2))

    final_value = res
    if target_os == "Windows":
        final_value = f"{res}|||{action_level}"

    return Payload(
        value=final_value,
        attack_type=m_parts[0],
        risk_level=m_parts[1],
    )