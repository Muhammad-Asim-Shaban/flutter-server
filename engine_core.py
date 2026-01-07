# engine_core.py
import os
import magic
import zipfile
from modules.OFFICE.office_checker import run_office_heuristics, run_office_signatures
from modules.EXE.exe_checker import run_exe_heuristics, run_exe_signatures
from modules.PDF.pdf_checker import run_pdf_heuristics, run_pdf_signatures
from modules.APK.apk_checker import run_apk_heuristics, run_apk_signatures

def analyze_file(file_path: str):
    if not os.path.isfile(file_path):
        return {"error": "File not found"}

    m = magic.Magic()
    info = m.from_file(file_path)

    result = {
        "file_type": info,
        "signatures": [],
        "heuristics": []
    }

    try:
        if ("Word" in info or "Excel" in info or "PowerPoint" in info):
            result["heuristics"] = run_office_heuristics(file_path)
            result["signatures"] = run_office_signatures(file_path)

        elif "PE32 executable" in info or "PE32+ executable" in info:
            result["heuristics"] = run_exe_heuristics(file_path)
            result["signatures"] = run_exe_signatures(file_path)

        elif "PDF document" in info:
            result["heuristics"] = run_pdf_heuristics(file_path)
            result["signatures"] = run_pdf_signatures(file_path)

        elif "Zip archive" in info and "AndroidManifest.xml" in zipfile.ZipFile(file_path).namelist():
            result["heuristics"] = run_apk_heuristics(file_path)
            result["signatures"] = run_apk_signatures(file_path)

        else:
            return {"error": "Unsupported file type"}

    except RuntimeError as e:
        return {"error": str(e)}

    return result
