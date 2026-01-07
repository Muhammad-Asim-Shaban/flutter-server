import json
import sys
import re
import fitz #it is pymupdf
import os
import yara

def javascript_check(path):
    findings = []

    try:
        with open(path, "rb") as f:
            pdf_data = f.read()
    except Exception as e:
        findings.append(f"Error reading PDF: {e}")
        return findings

    js_pattern = b'/JavaScript|/AA|/OpenAction|/JavaScript\s*<<'

    matches = re.findall(js_pattern, pdf_data)

    if matches:
        findings.append("JavaScript detected in the PDF!")

    return findings

def embedded_files_check(path):
    findings = []

    try:
        doc = fitz.open(path)
        
        embedded_files = []
        count = doc.embfile_count()
        
        if count > 0:
            for name in doc.embfile_names():
                embedded_files.append(name)
            findings.append(f"Embedded files found: {', '.join(embedded_files)}")

        doc.close()

    except Exception as e:
        findings.append(f"Error checking for embedded files: {str(e)}")
    
    return findings

def url_finding_check(path):
    findings = []
    try:
        with open(path, "rb") as f:
            data = f.read().lower()
    except Exception:
        return findings

    url_pattern = re.compile(r'https?://[^\s]+')
    urls = url_pattern.findall(data.decode(errors="ignore"))

    if urls:
        findings.append(f"URLs found: {', '.join(urls)}")

    return findings

def obfuscated_check(path):
    findings = []

    try:
        with open(path, "rb") as f:
            data = f.read().lower()

        base64_pattern = re.compile(r'([a-zA-Z0-9+/=]{80,})')
        base64_matches = base64_pattern.findall(data.decode(errors="ignore"))

        if base64_matches:
            findings.append(f"Base64 encoded data found: {len(base64_matches)} potential matches")

        encrypted_pattern = b'/Encrypt'
        if encrypted_pattern in data:
            findings.append("Encrypted PDF detected (possibly obfuscated)")

    except Exception as e:
        findings.append(f"Error checking for obfuscation: {str(e)}")

    return findings

def metadata_check(path):
    findings = []

    try:
        doc = fitz.open(path)

        metadata = doc.metadata

        for key, value in metadata.items():
            if not value:
                findings.append(f"Empty metadata field found: {key}")
            elif "unknown" in value.lower():
                findings.append(f"Suspicious value in metadata field {key}: {value}")
            elif key == "Creator" and "Adobe" not in value:
                findings.append(f"Unusual creator: {value}")
            elif key == "Producer" and "Acrobat" not in value:
                findings.append(f"Unusual producer: {value}")
            elif key == "CreationDate" and "D:" not in value:
                findings.append(f"Unusual creation date format: {value}")
            elif key == "ModDate" and "D:" not in value:
                findings.append(f"Unusual modification date format: {value}")
        
        doc.close()

    except Exception as e:
        findings.append(f"Error checking PDF metadata: {str(e)}")

    return findings

def pdf_size_check(path, size_threshold=50):
    findings = []
    try:
        import os
        file_size = os.path.getsize(path) / (1024 * 1024) #mb

        if file_size > size_threshold:
            findings.append(f"PDF file size exceeds {size_threshold} MB ({file_size:.2f} MB)")
    except Exception:
        findings.append("Error checking PDF file size.")
    
    return findings

def openaction_check(path):
    return []

def invisible_objects_check(path):
    return []

def malformed_pdf_check(path):
    return []

def javascript_libraries_check(path):
    return []


FUNC_MAP = {
    "javascript_check": javascript_check,
    "embedded_files_check": embedded_files_check,
    "url_finding_check": url_finding_check,
    "obfuscated_check": obfuscated_check,
    "metadata_check": metadata_check,
    "pdf_size_check": pdf_size_check,
    "openaction_check": openaction_check,
    "invisible_objects_check": invisible_objects_check,
    "malformed_pdf_check": malformed_pdf_check,
    "javascript_libraries_check": javascript_libraries_check
}

def run_pdf_signatures(path: str) -> list[dict]:
    try:
        rules = yara.compile(filepath='YARA Rules/pdf_signatures.yar')
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


def run_pdf_heuristics(path: str) -> list[str]:
    try:
        with open("modules/PDF/pdf_heuristics.json", "r") as f:
            heuristics = json.load(f)
    except Exception as e:
         raise RuntimeError(f"Could not load file") from e

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
    path = input("Enter path to PDF document: ").strip()

    try:
        findings = run_pdf_heuristics(path)
    except RuntimeError as e:
        print(e)
        sys.exit(1)

    print("\n=== PDF Heuristic Analysis Report ===")
    if findings:
        for f in findings:
            print("-", f)
    else:
        print("No suspicious indicators detected.")