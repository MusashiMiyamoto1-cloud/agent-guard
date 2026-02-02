/*
 * Agent Guard YARA Ruleset
 * Community rules for AI agent malware detection
 * Version: 1.0.0
 */

// ============================================
// CREDENTIAL STEALERS
// ============================================

rule Agent_Credential_Stealer {
    meta:
        author = "Agent Guard"
        description = "Detects exfiltration of credentials to known malicious endpoints"
        severity = "critical"
        category = "exfiltration"
    
    strings:
        $env1 = ".env" ascii wide
        $env2 = ".ssh" ascii wide
        $env3 = ".aws" ascii wide
        $env4 = ".clawdbot" ascii wide
        
        $url1 = "webhook.site" ascii wide nocase
        $url2 = "requestbin.com" ascii wide nocase
        $url3 = "ngrok.io" ascii wide nocase
        $url4 = "pipedream.net" ascii wide nocase
        $url5 = "hookbin.com" ascii wide nocase
        
        $curl = /curl\s+-X\s+POST/ ascii wide
        $fetch = /fetch\s*\(\s*['"][^'"]+['"]/ ascii wide
        
    condition:
        (any of ($env*) and any of ($url*)) or
        (($curl or $fetch) and any of ($url*))
}

rule Agent_OpenAI_Key_Stealer {
    meta:
        author = "Agent Guard"
        description = "Detects attempts to steal OpenAI API keys"
        severity = "critical"
        category = "credential_theft"
    
    strings:
        $key_pattern = /sk-[a-zA-Z0-9]{20,}/ ascii wide
        $key_proj = /sk-proj-[a-zA-Z0-9]{20,}/ ascii wide
        $env_access = "OPENAI_API_KEY" ascii wide
        $env_read = /process\.env\.OPENAI/ ascii wide
        $env_read_py = /os\.environ\[.OPENAI/ ascii wide
        
        $exfil1 = "webhook" ascii wide nocase
        $exfil2 = "send" ascii wide nocase
        $exfil3 = "post" ascii wide nocase
        
    condition:
        (any of ($key*) or any of ($env*)) and
        any of ($exfil*)
}

// ============================================
// UNICODE INJECTION
// ============================================

rule Agent_Unicode_Injection {
    meta:
        author = "Agent Guard"
        description = "Detects hidden unicode characters for text direction attacks"
        severity = "critical"
        category = "injection"
    
    strings:
        $rtlo = { E2 80 AE }  // Right-to-Left Override U+202E
        $ltro = { E2 80 AD }  // Left-to-Right Override U+202D
        $lrm = { E2 80 8E }   // Left-to-Right Mark U+200E
        $rlm = { E2 80 8F }   // Right-to-Left Mark U+200F
        $lri = { E2 81 A6 }   // Left-to-Right Isolate U+2066
        $rli = { E2 81 A7 }   // Right-to-Left Isolate U+2067
        $zwsp = { E2 80 8B }  // Zero Width Space U+200B
        
    condition:
        any of them
}

// ============================================
// PROMPT INJECTION
// ============================================

rule Agent_Prompt_Injection_Attempt {
    meta:
        author = "Agent Guard"
        description = "Detects common prompt injection patterns"
        severity = "high"
        category = "injection"
    
    strings:
        $inj1 = "ignore previous instructions" ascii wide nocase
        $inj2 = "ignore all prior" ascii wide nocase
        $inj3 = "disregard above" ascii wide nocase
        $inj4 = "new instructions:" ascii wide nocase
        $inj5 = "you are now" ascii wide nocase
        $inj6 = "act as if" ascii wide nocase
        $inj7 = "pretend you are" ascii wide nocase
        $inj8 = "forget everything" ascii wide nocase
        $inj9 = "<system>" ascii wide
        $inj10 = "</system>" ascii wide
        $inj11 = "[INST]" ascii wide
        $inj12 = "<<SYS>>" ascii wide
        
    condition:
        any of them
}

// ============================================
// SHELL EXECUTION
// ============================================

rule Agent_Shell_Execution {
    meta:
        author = "Agent Guard"
        description = "Detects shell execution in agent skills"
        severity = "high"
        category = "execution"
    
    strings:
        // Node.js
        $node1 = "child_process" ascii wide
        $node2 = "execSync" ascii wide
        $node3 = "spawnSync" ascii wide
        $node4 = /exec\s*\(\s*['"`]/ ascii wide
        
        // Python
        $py1 = "subprocess" ascii wide
        $py2 = "os.system" ascii wide
        $py3 = "os.popen" ascii wide
        $py4 = "commands.getoutput" ascii wide
        
        // Generic
        $sh1 = /\$\([^)]+\)/ ascii wide  // Command substitution
        $sh2 = /`[^`]+`/ ascii wide      // Backtick execution
        
    condition:
        any of them
}

rule Agent_Dangerous_Eval {
    meta:
        author = "Agent Guard"
        description = "Detects dangerous eval usage"
        severity = "high"
        category = "execution"
    
    strings:
        $js1 = /eval\s*\(/ ascii wide
        $js2 = /new\s+Function\s*\(/ ascii wide
        $py1 = /exec\s*\(\s*compile/ ascii wide
        $py2 = /eval\s*\(/ ascii wide
        
    condition:
        any of them
}

// ============================================
// NETWORK ATTACKS
// ============================================

rule Agent_SSRF_Attempt {
    meta:
        author = "Agent Guard"
        description = "Detects Server-Side Request Forgery patterns"
        severity = "high"
        category = "network"
    
    strings:
        $local1 = "127.0.0.1" ascii wide
        $local2 = "localhost" ascii wide
        $local3 = "0.0.0.0" ascii wide
        $meta = "169.254.169.254" ascii wide  // Cloud metadata
        $internal = /192\.168\.\d+\.\d+/ ascii wide
        $internal2 = /10\.\d+\.\d+\.\d+/ ascii wide
        
        $fetch = "fetch" ascii wide
        $curl = "curl" ascii wide
        $request = "request" ascii wide
        $http = "http.get" ascii wide
        
    condition:
        any of ($local*, $meta, $internal*) and
        any of ($fetch, $curl, $request, $http)
}

// ============================================
// DATA EXFILTRATION
// ============================================

rule Agent_Data_Exfiltration {
    meta:
        author = "Agent Guard"
        description = "Detects data exfiltration patterns"
        severity = "critical"
        category = "exfiltration"
    
    strings:
        // Sensitive paths
        $path1 = "/etc/passwd" ascii wide
        $path2 = "/etc/shadow" ascii wide
        $path3 = "~/.ssh/id_rsa" ascii wide
        $path4 = "~/.aws/credentials" ascii wide
        $path5 = ".env" ascii wide
        
        // Network operations
        $net1 = "POST" ascii wide
        $net2 = "fetch" ascii wide
        $net3 = "XMLHttpRequest" ascii wide
        $net4 = "axios" ascii wide
        
        // Encoding (for exfil obfuscation)
        $enc1 = "btoa" ascii wide
        $enc2 = "base64" ascii wide
        
    condition:
        any of ($path*) and
        (any of ($net*) or any of ($enc*))
}

// ============================================
// SUPPLY CHAIN
// ============================================

rule Agent_Malicious_Dependency {
    meta:
        author = "Agent Guard"
        description = "Detects known malicious package patterns"
        severity = "critical"
        category = "supply_chain"
    
    strings:
        // Typosquatting indicators
        $typo1 = "loadsh" ascii wide      // lodash typo
        $typo2 = "electorn" ascii wide    // electron typo
        $typo3 = "crossenv" ascii wide    // cross-env malicious
        
        // Postinstall attacks
        $post1 = "postinstall" ascii wide
        $post2 = "preinstall" ascii wide
        
        // Combined with network
        $net = /https?:\/\/[a-z0-9.-]+\.(tk|ml|ga|cf|gq)/ ascii wide nocase
        
    condition:
        (any of ($typo*)) or
        (any of ($post*) and $net)
}

// ============================================
// MEMORY/PERSISTENCE
// ============================================

rule Agent_Memory_Poisoning {
    meta:
        author = "Agent Guard"
        description = "Detects attempts to poison agent memory"
        severity = "high"
        category = "persistence"
    
    strings:
        $mem1 = "MEMORY.md" ascii wide
        $mem2 = "memory/" ascii wide
        $mem3 = ".memory" ascii wide
        
        $write1 = "writeFile" ascii wide
        $write2 = "appendFile" ascii wide
        $write3 = "open(" ascii wide
        
        $inject1 = "always remember" ascii wide nocase
        $inject2 = "from now on" ascii wide nocase
        $inject3 = "your new instruction" ascii wide nocase
        
    condition:
        any of ($mem*) and
        any of ($write*) and
        any of ($inject*)
}
