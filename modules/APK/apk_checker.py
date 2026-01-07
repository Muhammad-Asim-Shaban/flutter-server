from loguru import logger
logger.remove()  #silence logs

from androguard.core.apk import APK
import os
import json
import sys
import yara


def dangerous_permission_check(apk, keywords):
    findings = []
    perms = apk.get_permissions()
    for p in perms:
        for kw in keywords:
            if kw.lower() in p.lower():
                findings.append(f"Dangerous permission detected: {p}")
    return findings

def dangerous_intent_check(apk, keywords):
    findings = []
    manifest_xml = apk.get_android_manifest_xml()
    if manifest_xml is None:
        return findings

    for intent_filter in manifest_xml.findall(".//intent-filter"):
        for action in intent_filter.findall("action"):
            name = action.attrib.get("{http://schemas.android.com/apk/res/android}name", "")
            for kw in keywords:
                if kw.lower() in name.lower():
                    findings.append(f"Dangerous intent action detected: {name}")
    return findings



FUNC_MAP = {
    "dangerous_permission_check": dangerous_permission_check,
    "dangerous_intent_check": dangerous_intent_check,
}


def run_apk_signatures(path: str) -> list[dict]:
    try:
        rules = yara.compile(filepath='YARA Rules/apk_signatures.yar')
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


def run_apk_heuristics(path: str) -> list[str]:
    try:
        with open("modules/APK/apk_heuristics.json", "r") as f:
            heuristics = json.load(f)
    except Exception as e:
        raise RuntimeError("Could not load apk_heuristics.json") from e

    if not os.path.isfile(path):
        raise FileNotFoundError(f"APK not found: {path}")

    apk = APK(path)
    findings = []

    for h in heuristics:
        func = FUNC_MAP.get(h["function"])
        if not func:
            continue
        results = func(apk, h.get("keywords", []))
        for r in results:
            findings.append(f"[{h['severity']}] {r}")

    return findings

# optional standalone support
if __name__ == "__main__":
    apk_path = input("Enter APK file path: ").strip()
    try:
        results = run_apk_heuristics(apk_path)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

    print("\n=== APK Heuristic Analysis Report ===")
    if results:
        for f in results:
            print("-", f)
    else:
        print("No suspicious indicators detected.")
