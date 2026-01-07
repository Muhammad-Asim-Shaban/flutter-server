from oletools.olevba import VBA_Parser
import olefile
import json
import sys
import yara
import os

def macros_present_check(path):
    vba = VBA_Parser(path)
    try:
        if vba.detect_vba_macros():
            return ["VBA macros present in document"]
    finally:
        vba.close()
    return []

def large_macro_check(path, size_threshold=5000):
    findings = []
    vba = VBA_Parser(path)
    try:
        if not vba.detect_vba_macros():
            return findings

        total_size = 0
        for (_, _, _, code) in vba.extract_macros():
            total_size += len(code)

        if total_size > size_threshold:
            findings.append(f"Large VBA macro detected ({total_size} bytes)")
    finally:
        vba.close()

    return findings

def social_engineering_check(path, keywords):
    findings = []
    try:
        with open(path, "rb") as f:
            data = f.read().lower()
    except Exception:
        return findings

    for s in keywords:
        if s.encode() in data:
            findings.append(f"Social engineering prompt detected: '{s}'")

    return findings

def autoexec_macro_check(path, keywords):
    findings = []
    vba = VBA_Parser(path)
    try:
        if not vba.detect_vba_macros():
            return findings

        for (_, _, _, code) in vba.extract_macros():
            code_lower = code.lower()
            for k in keywords:
                if k in code_lower:
                    findings.append(f"Auto-executing VBA macro found: {k}")
    finally:
        vba.close()

    return findings

def suspicious_vba_function_check(path, keywords):
    findings = []
    vba = VBA_Parser(path)
    try:
        if not vba.detect_vba_macros():
            return findings

        for (_, _, _, code) in vba.extract_macros():
            code_lower = code.lower()
            for f in keywords:
                if f in code_lower:
                    findings.append(f"Suspicious VBA function used: {f}")
    finally:
        vba.close()

    return findings

def embedded_ole_object_check(path):
    findings = []

    if olefile.isOleFile(path):
        ole = olefile.OleFileIO(path)
        try:
            for stream in ole.listdir():
                if "oleobject" in "/".join(stream).lower():
                    findings.append("Embedded OLE object detected")
                    break
        finally:
            ole.close()
        return findings

    if path.lower().endswith(("docx", "xlsx", "pptx", "docm", "xlsm", "pptm")):
        try:
            import zipfile
            with zipfile.ZipFile(path) as z:
                for name in z.namelist():
                    if "embeddings/oleobject" in name.lower():
                        findings.append("Embedded OLE object detected")
                        break
        except Exception:
            pass

    return findings

FUNC_MAP = {
    "macros_present_check": macros_present_check,
    "large_macro_check": large_macro_check,
    "social_engineering_check": social_engineering_check,
    "autoexec_macro_check": autoexec_macro_check,
    "suspicious_vba_function_check": suspicious_vba_function_check,
    "embedded_ole_object_check": embedded_ole_object_check
}

def run_office_signatures(path: str) -> list[dict]:
    try:
        rules = yara.compile(filepath='YARA Rules/office_signatures.yar')
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


def run_office_heuristics(path: str) -> list[str]:
    try:
        with open("modules/OFFICE/office_heuristics.json", "r") as f:
            heuristics = json.load(f)
    except Exception as e:
        raise RuntimeError("Could not load office_heuristics.json") from e

    findings = []

    for h in heuristics:
        func = FUNC_MAP.get(h["function"])
        if not func:
            continue

        if "keywords" in h:
            results = func(path, h["keywords"])
        elif "size_threshold" in h:
            results = func(path, h["size_threshold"])
        else:
            results = func(path)

        for r in results:
            findings.append(f"[{h['severity']}] {r}")

    return findings

#optional standalone support
if __name__ == "__main__":
    path = input("Enter path to Office document: ").strip()

    try:
        findings = run_office_heuristics(path)
    except RuntimeError as e:
        print(e)
        sys.exit(1)

    print("\n=== Heuristic Analysis Report ===")
    if findings:
        for f in findings:
            print("-", f)
    else:
        print("No suspicious indicators detected.")