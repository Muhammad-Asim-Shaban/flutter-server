import sys
import os
import magic
import zipfile
from modules.OFFICE.office_checker import run_office_heuristics
from modules.OFFICE.office_checker import run_office_signatures
from modules.EXE.exe_checker import run_exe_heuristics
from modules.EXE.exe_checker import run_exe_signatures
from modules.PDF.pdf_checker import run_pdf_heuristics
from modules.PDF.pdf_checker import run_pdf_signatures
from modules.APK.apk_checker import run_apk_heuristics
from modules.APK.apk_checker import run_apk_signatures

# usage help
if len(sys.argv) < 2:
    print("usage: engine.py <file>")
    sys.exit(1)

# searching if such a file exists or not
file_path = sys.argv[1]
if not os.path.isfile(file_path):
    print(f"engine: cannot access '{file_path}': No such file")
    sys.exit(1)

# making magic ready to read magic words from file
m = magic.Magic()
info = m.from_file(file_path)
print(f"File: {info}")



# micorsoft office files
if ("Word" in info or "Excel" in info or "PowerPoint" in info):
    try:
        heuristic_results = run_office_heuristics(file_path)
        signature_results = run_office_signatures(file_path)
    except RuntimeError as e:
        print("Error:", e) 
    else:
        print("\n=== Signature Analysis Report ===")
        if signature_results:
            for match in signature_results:
                print(f"Rule Name: {match['rule_name']}")
                print(f"Meta: {match['meta']}")
        else:
            print("No matching signatures detected.")

        print("\n=== Heuristic Analysis Report ===")
        if heuristic_results:
            for r in heuristic_results:
                print("-", r)
        else:
            print("No suspicious heuristics detected.")

# portable executables
elif "PE32 executable" in info or "PE32+ executable" in info:
    try:
        heuristic_results = run_exe_heuristics(file_path)
        signature_results = run_exe_signatures(file_path)
    except RuntimeError as e:
        print("Error:", e) 
    else:
        print("\n=== Signature Analysis Report ===")
        if signature_results:
            for match in signature_results:
                print(f"Rule Name: {match['rule_name']}")
                print(f"Meta: {match['meta']}")
        else:
            print("No matching signatures detected.")

        print("\n=== Heuristic Analysis Report ===")
        if heuristic_results:
            for r in heuristic_results:
                print("-", r)
        else:
            print("No suspicious heuristics detected.")

# PDF'sl
elif "PDF document" in info:
    try:
        heuristic_results = run_pdf_heuristics(file_path)
        signature_results = run_pdf_signatures(file_path)
    except RuntimeError as e:
        print("Error:", e) 
    else:
        print("\n=== Signature Analysis Report ===")
        if signature_results:
            for match in signature_results:
                print(f"Rule Name: {match['rule_name']}")
                print(f"Meta: {match['meta']}")
        else:
            print("No matching signatures detected.")

        print("\n=== Heuristic Analysis Report ===")
        if heuristic_results:
            for r in heuristic_results:
                print("-", r)
        else:
            print("No suspicious heuristics detected.")

# APK's
elif "Zip archive" in info and "AndroidManifest.xml" in (zipfile.ZipFile(file_path).namelist()):
    try:
        heuristic_results = run_apk_heuristics(file_path)
        signature_results = run_apk_signatures(file_path)
    except RuntimeError as e:
        print("Error:", e) 
    else:
        print("\n=== Signature Analysis Report ===")
        if signature_results:
            for match in signature_results:
                print(f"Rule Name: {match['rule_name']}")
                print(f"Meta: {match['meta']}")
        else:
            print("No matching signatures detected.")

        print("\n=== Heuristic Analysis Report ===")
        if heuristic_results:
            for r in heuristic_results:
                print("-", r)
        else:
            print("No suspicious heuristics detected.")

else:
    print("engine: unsupported file type")
    sys.exit(1)

