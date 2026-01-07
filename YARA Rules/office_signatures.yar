rule Office_Macro
{
    meta:
        description = "Detects malicious macros in Office documents"
    
    strings:
        $macro1 = "VBA" ascii
        $macro2 = "Shell" ascii
        $macro3 = "CreateObject" ascii
        $macro4 = "Execute" ascii
        $macro5 = "cmd.exe" ascii

    condition:
        any of ($macro1, $macro2, $macro3, $macro4) and
        $macro5
}


rule Office_Macro_Obfuscation
{
    meta:
        description = "Detects obfuscated macros in Office files"
    
    strings:
        $obfuscation1 = "chr(" ascii
        $obfuscation2 = "mid(" ascii
        $obfuscation3 = "eval(" ascii
        $obfuscation4 = "replace(" ascii

    condition:
        any of ($obfuscation1, $obfuscation2, $obfuscation3, $obfuscation4)
}

rule Office_Embedded_Suspicious_Object
{
    meta:
        description = "Detects suspicious embedded objects in Office files"
    
    strings:
        $ole = "OLE" ascii
        $embedded = "EmbeddedObject" ascii
        $shell = "Shell" ascii
        $run = "Run" ascii

    condition:
        any of ($ole, $embedded) and
        any of ($shell, $run)
}

rule Office_Suspicious_Registry_Keys
{
    meta:
        description = "Detects suspicious registry keys often used by Office malware"
    
    strings:
        $regkey1 = "Software\\Microsoft\\Office\\Excel\\Security" ascii
        $regkey2 = "Software\\Microsoft\\Office\\Word\\Security" ascii
        $regkey3 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $regset = "RegSetValueEx" ascii

    condition:
        any of ($regkey1, $regkey2, $regkey3) and
        $regset
}

rule Office_Exploit_Attempts
{
    meta:
        description = "Detects Office files with exploit attempts"
    
    strings:
        $shellcode = { 6A 00 68 ?? ?? ?? ?? 6A 00 6A 00 68 ?? ?? ?? ?? 6A 00 }
        $hresult = "HRESULT" ascii
        $dispatch = "IDispatch" ascii

    condition:
        $shellcode or
        any of ($hresult, $dispatch)
}

rule Office_Persistence_VBA_Auto_Open
{
    meta:
        description = "Detects use of AutoOpen or AutoExec macros for persistence in Office files"
    
    strings:
        $autoopen = "AutoOpen" ascii
        $autoexec = "AutoExec" ascii
        $vba = "VBA" ascii

    condition:
        any of ($autoopen, $autoexec) and
        $vba
}

rule Office_Suspicious_XML_Payload
{
    meta:
        description = "Detects suspicious XML payloads embedded in Office files"
    
    strings:
        $xml = "<?xml" ascii
        $payload = "<payload>" ascii
        $script = "<script>" ascii
        $exec = "<exec>" ascii

    condition:
        $xml and
        any of ($payload, $script, $exec)
}

rule Office_Malicious_Pivot_Files
{
    meta:
        description = "Detects Office files that pivot to other malicious files"
    
    strings:
        $pivot = "pivot" ascii
        $exe = ".exe" ascii
        $script = ".vbs" ascii
        $cmd = ".cmd" ascii

    condition:
        any of ($pivot) and
        any of ($exe, $script, $cmd)
}

rule Office_DDE_Exploitation
{
    meta:
        description = "Detects DDE (Dynamic Data Exchange) exploitation in Office files"
    
    strings:
        $dde = "DDE" ascii
        $autoopen = "AutoOpen" ascii
        $eval = "EVAL" ascii

    condition:
        any of ($dde, $autoopen) and
        $eval
}

rule Office_Suspicious_Base64_Encoding
{
    meta:
        description = "Detects suspicious Base64 encoded payloads in Office files"
    
    strings:
        $base64 = "BASE64" ascii
        $encoded = "encoded" ascii
        $decode = "decode" ascii

    condition:
        any of ($base64, $encoded) and
        $decode
}

rule Office_Macro_Behavior_Abnormal
{
    meta:
        description = "Detects abnormal behavior patterns of macros in Office files"
    
    strings:
        $macro = "Macro" ascii
        $vba = "VBA" ascii
        $suspend = "Suspend" ascii
        $sleep = "Sleep" ascii

    condition:
        $macro and
        $vba and
        any of ($suspend, $sleep)
}
