# engine_core.py

import os
import magic
import zipfile

from modules.OFFICE.office_checker import (
    run_office_heuristics,
    run_office_signatures
)
from modules.EXE.exe_checker import (
    run_exe_heuristics,
    run_exe_signatures
)
from modules.PDF.pdf_checker import (
    run_pdf_heuristics,
    run_pdf_signatures
)
from modules.APK.apk_checker import (
    run_apk_heuristics,
    run_apk_signatures
)

# Fixed: Changed from dynamic_anlaysis to dynamic_analysis
from modules.dynamic_analysis import DynamicAnalyzer


# Initialize dynamic analyzer
dynamic_analyzer = DynamicAnalyzer()


def analyze_file(file_path: str):
    """
    Perform static (signature + heuristic) and dynamic analysis
    """

    if not os.path.isfile(file_path):
        return {"error": "File not found"}

    # Detect file type
    try:
        m = magic.Magic()
        file_info = m.from_file(file_path)
    except Exception as e:
        return {"error": f"File type detection failed: {str(e)}"}

    result = {
        "file_type": file_info,
        "signatures": [],
        "heuristics": [],
        "runtime_behavior": {}   # Dynamic analysis
    }

    try:
        # ---------------- STATIC ANALYSIS ---------------- #

        # Microsoft Office documents
        if "Word" in file_info or "Excel" in file_info or "PowerPoint" in file_info:
            result["heuristics"] = run_office_heuristics(file_path)
            result["signatures"] = run_office_signatures(file_path)

        # Windows PE executables
        elif "PE32 executable" in file_info or "PE32+ executable" in file_info:
            result["heuristics"] = run_exe_heuristics(file_path)
            result["signatures"] = run_exe_signatures(file_path)

        # PDF documents
        elif "PDF document" in file_info:
            result["heuristics"] = run_pdf_heuristics(file_path)
            result["signatures"] = run_pdf_signatures(file_path)

        # Android APK
        elif (
            "Zip archive" in file_info and
            "AndroidManifest.xml" in zipfile.ZipFile(file_path).namelist()
        ):
            result["heuristics"] = run_apk_heuristics(file_path)
            result["signatures"] = run_apk_signatures(file_path)

        else:
            return {"error": "Unsupported file type"}

        # ---------------- DYNAMIC ANALYSIS ---------------- #
        print(f"🔍 Starting dynamic analysis for: {os.path.basename(file_path)}")
        
        file_name = os.path.basename(file_path)
        runtime_result = dynamic_analyzer.analyze_file(file_path, file_name)
        
        result["runtime_behavior"] = runtime_result
        print(f"✅ Dynamic analysis completed: {runtime_result.get('threat_level', 'UNKNOWN')}")

    except RuntimeError as e:
        return {"error": str(e)}
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"error": f"Analysis error: {str(e)}"}

    return result