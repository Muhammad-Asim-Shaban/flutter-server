rule Detect_RAT_Apk {
  meta:
    description = "Detects APKs associated with common Remote Access Trojans (e.g., NjRat, DroidJack)"
  strings:
    $rat_string_1 = "njrat" ascii
    $rat_string_2 = "droidjack" ascii
    $rat_string_3 = "reverse_tcp" ascii
    $rat_string_4 = "GET / HTTP/1.1" ascii
    $rat_string_5 = "POST / HTTP/1.1" ascii
    $ip_pattern = { 01 02 03 04 } // Generic IP address pattern (for example, embedded C2 server IP)
  condition:
    any of ($rat_string_1, $rat_string_2) and 
    any of ($rat_string_3, $rat_string_4, $rat_string_5) and 
    $ip_pattern
}

rule Detect_Hardcoded_Credentials {
  meta:
    description = "Detects APKs with hardcoded credentials or passwords commonly used in spyware or keyloggers"
  strings:
    $username_pattern = /username=[a-zA-Z0-9]{6,20}/ 
    $password_pattern = /password=[a-zA-Z0-9]{6,20}/
    $api_key_pattern = /api_key=[A-Za-z0-9]{32}/
  condition:
    any of ($username_pattern, $password_pattern, $api_key_pattern)
}


rule Detect_Hardcoded_C2_Urls {
  meta:
    description = "Detects APKs with hardcoded C2 server URLs commonly found in APT backdoors"
  strings:
    $c2_url_1 = "http://example.com" ascii
    $c2_url_2 = "https://attackerserver.com" ascii
    $c2_ip = { C0 A8 00 01 } // Hardcoded C2 IP (example: 192.168.0.1)
  condition:
    any of ($c2_url_1, $c2_url_2) or $c2_ip
}


rule Detect_Code_Injection_Metasploit {
  meta:
    description = "Detects APKs that attempt to inject code using techniques like Metasploit's reflective injection"
  strings:
    $reflection_1 = "java.lang.reflect" ascii
    $reflection_2 = "Method.invoke" ascii
    $reflection_3 = "Landroid/os/RemoteException;" ascii
    $payload_signature = { 4D 45 54 45 52 50 52 45 54 } // METERPRETER signature in code
  condition:
    any of ($reflection_1, $reflection_2) and $reflection_3 and $payload_signature
}
