import pefile
import os
import math
import re
import datetime
import json
from collections import Counter
import yara

def get_entropy(data):
    if not data:
        return 0.0
    freq = Counter(data)
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def extract_strings_once(file_path, min_len=5):
    with open(file_path, "rb") as f:
        data = f.read()
    pattern = rb"[ -~]{%d,}" % min_len
    return [s.decode(errors="ignore") for s in re.findall(pattern, data)]

def file_size_check(pe, path):
    size = os.path.getsize(path)
    findings = []
    if size < 20 * 1024:
        findings.append(f"File size very small ({size} bytes)")
    if size > 30 * 1024 * 1024:
        findings.append(f"File size very large ({size} bytes)")
    return findings

def metadata_check(pe, path):
    findings = []
    if hasattr(pe, "FileInfo"):
        for info in pe.FileInfo:
            if info.Key == b"StringFileInfo":
                for st in info.StringTable:
                    if not st.entries.get(b"CompanyName", b"").strip():
                        findings.append("CompanyName metadata missing")
                    if not st.entries.get(b"ProductName", b"").strip():
                        findings.append("ProductName metadata missing")
    return findings

def signature_check(pe, path):
    if not hasattr(pe, "DIRECTORY_ENTRY_SECURITY"):
        return ["EXE is not digitally signed"]
    return []

def timestamp_check(pe, path):
    ts = pe.FILE_HEADER.TimeDateStamp

    if ts == 0:
        return ["Compilation timestamp missing (TimeDateStamp is zero)"]

    try:
        dt = datetime.datetime.utcfromtimestamp(ts)
        now = datetime.datetime.utcnow()
        if dt.year < 1995 or dt > now + datetime.timedelta(days=365):
            return [f"Unusual compilation timestamp ({dt})"]
    except Exception:
        return ["Invalid compilation timestamp"]

    return []

def entry_point_check(pe, path):
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    sec = pe.get_section_by_rva(ep)
    if sec and not (sec.Characteristics & 0x20):
        name = sec.Name.decode(errors="ignore").strip("\x00")
        return [f"Entry point not in executable code section ({name})"]
    return []

def section_count_check(pe, path):
    n = pe.FILE_HEADER.NumberOfSections
    findings = []
    if n < 2:
        findings.append(f"Very few sections ({n})")
    if n > 10:
        findings.append(f"Many sections ({n})")
    return findings

def section_name_check(pe, path):
    findings = []
    for sec in pe.sections:
        name = sec.Name.decode(errors="ignore").strip("\x00")
        if not name.startswith("."):
            findings.append(f"Non-standard section name: {name}")
    return findings

def rwx_section_check(pe, path):
    findings = []
    WRITE = 0x80000000
    EXEC = 0x20000000
    for sec in pe.sections:
        c = sec.Characteristics
        if (c & WRITE) and (c & EXEC):
            name = sec.Name.decode(errors="ignore").strip("\x00")
            findings.append(f"Section {name} is writable + executable (RWX)")
    return findings

def entropy_check(pe, path):
    findings = []
    for sec in pe.sections:
        ent = get_entropy(sec.get_data())
        if ent > 7.0:
            name = sec.Name.decode(errors="ignore").strip("\x00")
            findings.append(f"High entropy section {name} ({ent:.2f})")
    return findings

def dominant_section_check(pe, path):
    total = sum(sec.SizeOfRawData for sec in pe.sections)
    findings = []
    for sec in pe.sections:
        if total > 0 and sec.SizeOfRawData / total > 0.7:
            name = sec.Name.decode(errors="ignore").strip("\x00")
            findings.append(f"Single dominant section {name}")
    return findings

def dynamic_api_check(pe, path, keywords):
    found = set()

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for dll in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in dll.imports:
                if imp.name:
                    name = imp.name.decode(errors="ignore")
                    if name in keywords:
                        found.add(name)

    if found:
        return [f"Dynamic APIs found: {', '.join(sorted(found))}"]

    return []

def tls_check(pe, path):
    if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
        return ["TLS callbacks present (pre-main execution)"]
    return []

def network_string_check(pe, path, strings, ignore_patterns, keywords=None):
    findings = []
    if keywords is None:
        keywords = []
    for s in strings:
        if any(re.search(p, s) for p in ignore_patterns):
            continue
        for k in keywords:
            if k.lower() in s.lower():
                findings.append(f"Hardcoded URL/IP found: {s}")
    return findings

def command_string_check(pe, path, strings, ignore_patterns, keywords=None):
    findings = []
    if keywords is None:
        keywords = []
    for s in strings:
        if any(re.search(p, s) for p in ignore_patterns):
            continue
        for k in keywords:
            if k.lower() in s.lower():
                findings.append(f"Command execution string found: {s}")
                break
    return findings

def registry_string_check(pe, path, strings, ignore_patterns, keywords=None):
    findings = []
    if keywords is None:
        keywords = []
    for s in strings:
        if any(re.search(p, s) for p in ignore_patterns):
            continue
        for k in keywords:
            if k.lower() in s.lower():
                findings.append(f"Autorun registry path found: {s}")
    return findings


FUNC_MAP = {
    "file_size_check": file_size_check,
    "metadata_check": metadata_check,
    "signature_check": signature_check,
    "timestamp_check": timestamp_check,
    "entry_point_check": entry_point_check,
    "section_count_check": section_count_check,
    "section_name_check": section_name_check,
    "rwx_section_check": rwx_section_check,
    "entropy_check": entropy_check,
    "dominant_section_check": dominant_section_check,
    "dynamic_api_check": dynamic_api_check,
    "tls_check": tls_check,
    "network_string_check": network_string_check,
    "command_string_check": command_string_check,
    "registry_string_check": registry_string_check
}

def run_exe_signatures(path: str) -> list[dict]:
    try:
        rules = yara.compile(filepath='YARA Rules/exe_signatures.yar')
    except yara.Error as e:
        print(f"YARA rule compilation error: {e}")
        exit()
    
    if not os.path.exists(path):
        print(f"Error: {path} does not exist.")
        exit()
    
    print(f"Scanning file: {path}")
    matches = rules.match(filepath=path)
    
    if matches:
        results = []
        for match in matches:
            results.append({
                'rule_name': match.rule,
                'meta': match.meta
            })
        return results
    else:
        return []


def run_exe_heuristics(path: str) -> list[str]:
    pe = pefile.PE(path)

    try:
        with open("modules/EXE/exe_heuristics.json", "r") as f:
            heuristics = json.load(f)
    except Exception as e:
        raise RuntimeError("Could not load exe_heuristics.json") from e

    strings = extract_strings_once(path)
    findings = []

    for h in heuristics:
        func = FUNC_MAP.get(h["function"])
        if not func:
            continue

        ignore_patterns = h.get("ignore_patterns", [])
        keywords = h.get("keywords", [])

        if h["function"] == "dynamic_api_check":
            results = func(pe, path, keywords)

        elif h["function"] in (
            "network_string_check",
            "command_string_check",
            "registry_string_check",
        ):
            results = func(pe, path, strings, ignore_patterns, keywords)

        else:
            results = func(pe, path)

        for r in results:
            findings.append(f"[{h['severity']}] {r}")

    return findings

# optional standalone support
if __name__ == "__main__":
    path = input("Enter path to EXE file: ").strip()

    try:
        findings = run_exe_heuristics(path)
    except RuntimeError as e:
        print(e)
        exit(1)

    print("\n=== Heuristic Analysis Report ===")
    if findings:
        for f in findings:
            print("-", f)
    else:
        print("No suspicious indicators detected.")
