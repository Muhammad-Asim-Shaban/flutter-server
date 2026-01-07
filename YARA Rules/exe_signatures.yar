rule Meterpreter_Reverse_Tcp { 
    meta:
        description = "Meterpreter reverse TCP backdoor in memory. Tested on Win7x64." 
    strings: 
        $a = { 4d 45 54 45 52 50 52 45 54 45 52 5f 54 52 41 4e 53 50 4f 52 54 5f 53 53 4c [32-48] 68 74 74 70 73 3a 2f 2f 58 58 58 58 58 58 } // METERPRETER_TRANSPORT_SSL … https://XXXXXX 
        $b = { 4d 45 54 45 52 50 52 45 54 45 52 5f 55 41 }
        $c = { 47 45 54 20 2f 31 32 33 34 35 36 37 38 39 20 48 54 54 50 2f 31 2e 30 } // GET /123456789 HTTP/1.0 
        $d = { 6d 65 74 73 72 76 2e 64 6c 6c [2-4] 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } // metsrv.dll … ReflectiveLoader 
      
    condition: 
        $a or (any of ($b, $d) and $c) 
}

rule PE_Uses_Process_Injection_APIs
{
    meta:
        description = "Detects common process injection techniques"
    
    strings:
        $openproc = "OpenProcess" ascii
        $virtalloc = "VirtualAllocEx" ascii
        $writeproc = "WriteProcessMemory" ascii
        $createthread = "CreateRemoteThread" ascii
        $isdebug = "IsDebuggerPresent" ascii
        $ntquery = "NtQueryInformationProcess" ascii

    condition:
        3 of ($openproc, $virtalloc, $writeproc, $createthread) and
        any of ($isdebug, $ntquery)
}

rule PE_Uses_Download_Execution
{
    meta:
        description = "Detects executables that download and execute content from the internet"
    
    strings:
        $urlmon = "URLDownloadToFile" ascii
        $wininet = "InternetOpenA" ascii
        $http = "http://" ascii nocase
        $https = "https://" ascii nocase
        $cmd = "cmd.exe" ascii
        $powershell = "powershell.exe" ascii
        $bitsadmin = "bitsadmin.exe" ascii

    condition:
        (any of ($urlmon, $wininet, $bitsadmin)) and
        (any of ($http, $https)) and
        any of ($cmd, $powershell)
}

rule PE_Uses_Persistence_Registry_Run
{
    meta:
        description = "Detects malware that uses registry Run keys for persistence"
    
    strings:
        $run1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $run2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii
        $regset = "RegSetValueEx" ascii

    condition:
        any of ($run1, $run2) and
        $regset
}

rule PE_Anti_Debug_Techniques
{
    meta:
        description = "Detects malware using anti-debugging techniques"

    strings:
        $isdebug = "IsDebuggerPresent" ascii
        $ntquery = "NtQueryInformationProcess" ascii
        $debugstr = "BeingDebugged" ascii
        $loadlib = "LoadLibraryA" ascii

    condition:
        3 of ($isdebug, $ntquery, $debugstr, $loadlib)
}

rule PE_Packed_Or_Obfuscated
{
    meta:
        description = "Detects likely packed or obfuscated executables"
    
    strings:
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $aspack = "ASPack" ascii
        $themida = "Themida" ascii
        $fsg = "FSG" ascii
        $mpress = "MPress" ascii

    condition:
        any of ($upx1, $upx2, $aspack, $themida, $fsg, $mpress)
}

rule PE_Credential_Access_Indicators
{
    meta:
        description = "Detects credential dumping activity"

    strings:
        $lsa = "LSASS" ascii
        $minidump = "MiniDumpWriteDump" ascii
        $seDebug = "SeDebugPrivilege" ascii
        $dpapi = "DPAPI" ascii

    condition:
        3 of ($lsa, $minidump, $seDebug, $dpapi)
}


rule PE_Fileless_Malware
{
    meta:
        description = "Detects fileless malware behaviors"
    
    strings:
        $wmi = "WMI" ascii
        $powershell = "powershell" ascii
        $injectdll = "InjectDll" ascii
        $mshta = "mshta.exe" ascii

    condition:
        any of ($wmi, $powershell, $mshta) and
        not $injectdll
}
