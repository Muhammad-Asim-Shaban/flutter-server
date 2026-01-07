rule Detect_PDF_Exploit_CVE_2017_11292 {
    meta:
        description = "Detects known exploit patterns in PDFs related to CVE-2017-11292"
    strings:
        $exploit_pattern = { 2F 44 65 73 63 72 69 70 74 6F 72 2F 48 65 61 64 65 72 20 2F 4C 69 6E 65 0A 2F 43 6F 6D 6D 65 6E 74 } 
    condition:
        $exploit_pattern
}

rule Detect_Embedded_Executable_in_PDF {
    meta:
        description = "Detects PDFs with embedded executable files, a common technique for delivering malware"
    strings:
        $exe_header = { 4D 5A 90 00 03 00 00 00 }  // 'MZ' header for executables
        $pdf_start = "%PDF-" ascii
    condition:
        $exe_header and $pdf_start
}
