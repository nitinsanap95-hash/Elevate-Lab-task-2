# Elevate-Lab-Project Question & Answers


**1. What is cybersecurity and why is it important?**

**Cybersecurity** is the practice of protecting computer systems, networks, software, and data from digital attacks, unauthorized access, damage, or theft. It encompasses a broad range of technologies, processes, and practices designed to safeguard information and ensure its confidentiality, integrity, and availability.

**Importance:**  
- **Protects Sensitive Data:** Prevents unauthorized access to personal, financial, and business information.
- **Ensures Business Continuity:** Safeguards operations from disruptions caused by cyber attacks.
- **Maintains Trust:** Builds confidence among customers, partners, and stakeholders.
- **Prevents Financial Loss:** Reduces costs associated with breaches, including fines, recovery, and lost revenue.
- **Compliance:** Helps organizations meet regulatory and legal requirements (e.g., GDPR, HIPAA).


**2. What’s the difference between a threat, a vulnerability, and a risk?**

- **Threat:** Any circumstance or event that has the potential to cause harm to an information system. Examples include malware, hackers, natural disasters, or insider attacks.
- **Vulnerability:** A weakness or flaw in a system, network, or process that can be exploited by a threat. Examples: outdated software, weak passwords, misconfigured firewalls.
- **Risk:** The potential for loss or damage when a threat exploits a vulnerability. Risk is typically measured by the likelihood and impact of such an event.

**Relationship:**  
Risk exists when a threat can exploit a vulnerability. Managing risk involves identifying threats and vulnerabilities, and applying controls to mitigate them.


**3. Define CIA triad (Confidentiality, Integrity, Availability).**

The **CIA triad** is the foundational model for information security:

- **Confidentiality:** Ensuring that information is accessible only to those authorized to have access. Methods include encryption, access controls, and authentication.
- **Integrity:** Protecting data from being altered, tampered with, or deleted by unauthorized parties. Methods include hashing, checksums, and audit logs.
- **Availability:** Ensuring that information and resources are accessible when needed. Methods include redundant systems, backups, and disaster recovery plans.

Balancing these three principles is crucial for effective security.


**4. What is the difference between IDS and IPS?**

- **IDS (Intrusion Detection System):**  
  Monitors network or system activities for malicious actions or policy violations. IDS detects and alerts administrators about suspicious activity but does not take direct action to block it.

- **IPS (Intrusion Prevention System):**  
  Similar to IDS but actively prevents or blocks detected threats. IPS can automatically take actions like dropping malicious packets, blocking IPs, or resetting connections.

**Key Difference:**  
IDS is passive (detects and alerts), while IPS is active (detects and prevents).


**5. What is the difference between symmetric and asymmetric encryption?**

- **Symmetric Encryption:**  
  Uses the same key for both encryption and decryption. Examples: AES, DES.  
  - **Pros:** Fast and efficient for large data.
  - **Cons:** Key distribution is challenging; if the key is compromised, all data is vulnerable.

- **Asymmetric Encryption:**  
  Uses a pair of keys: a public key for encryption and a private key for decryption. Examples: RSA, ECC.  
  - **Pros:** Secure key exchange; public key can be widely distributed.
  - **Cons:** Slower and computationally intensive compared to symmetric methods.

**Usage:** Often, asymmetric encryption is used to exchange symmetric keys securely.


**6. What is the principle of least privilege?**

The **principle of least privilege (PoLP)** means giving users, applications, and systems only the minimum level of access necessary to perform their tasks. By restricting privileges:
- Reduces potential attack surfaces.
- Limits the impact of compromised accounts.
- Enhances overall security by preventing unauthorized actions.

This principle applies to user permissions, network access, and software processes.


**7. Explain the difference between hashing and encryption.**

- **Hashing:**  
  Converts data into a fixed-size string (hash value) using a mathematical function. It’s a one-way process — hashes cannot be reversed to retrieve the original data. Used for data integrity checks, password storage, and digital signatures. Examples: SHA-256, MD5.

- **Encryption:**  
  Converts data into an unreadable format using an algorithm and encryption key. It’s reversible — encrypted data can be decrypted back to its original form with the correct key. Used for confidentiality and secure communication.

**Summary:**  
Hashing = one-way, used for integrity; Encryption = two-way, used for confidentiality.


**8. What is two-factor authentication (2FA) and how does it work?**

**Two-Factor Authentication (2FA)** is a security mechanism that requires two separate forms of identification to verify a user’s identity, typically combining:
- Something you know (password or PIN)
- Something you have (phone, security token, smart card)
- Something you are (biometric, e.g., fingerprint or face recognition)

**How it works:**  
After entering a password, users must provide a second factor, such as a code sent to their phone or generated by an app. This adds a layer of security, making it harder for attackers to gain access even if a password is compromised.


**9. What is the difference between black hat, white hat, and grey hat hackers?**

- **Black Hat Hackers:**  
  Individuals who break into systems for malicious purposes, such as theft, destruction, or unauthorized access. Their activities are illegal.

- **White Hat Hackers:**  
  Ethical hackers who use their skills to help organizations find and fix security vulnerabilities. They work with permission and often as part of security teams.

- **Grey Hat Hackers:**  
  Operate in the middle ground; may violate laws or ethical standards but without malicious intent. For example, they might find and report vulnerabilities without authorization or seek rewards for their discovery.

**10. What are some common cyber attack vectors?**

**Attack vectors** are methods or paths used by cybercriminals to gain unauthorized access or deliver malicious payloads:

- **Phishing:** Fraudulent emails or messages tricking users into revealing sensitive information.
- **Malware:** Software designed to harm or exploit systems (viruses, worms, ransomware, trojans).
- **Social Engineering:** Manipulating individuals into divulging confidential information.
- **Man-in-the-Middle (MitM):** Intercepting and altering communications between parties.
- **Drive-by Downloads:** Unintentional download of malicious software when visiting compromised websites.
- **Unpatched Software:** Exploiting vulnerabilities in outdated or unpatched applications.
- **Brute Force Attacks:** Systematic guessing of passwords or encryption keys.
- **Insider Threats:** Employees or contractors misusing access privileges.
- **Denial of Service (DoS/DDoS):** Overloading systems to make them unavailable.


**11. What is a firewall and how does it work?**  
A firewall is a security device (hardware or software) that monitors and controls incoming and outgoing network traffic based on predetermined security rules. It acts as a barrier between trusted internal networks and untrusted external networks (like the internet), blocking or allowing traffic based on rules set by the administrator.


**12. What is a DMZ in network security?**  
A DMZ (Demilitarized Zone) is a physical or logical subnetwork that contains and exposes an organization’s external-facing services to an untrusted network, typically the internet. It isolates these services from the internal network, reducing the risk that an attack on public servers will affect internal systems.


**13. What are the different types of firewalls?**  
- **Packet Filtering Firewall:** Inspects packets and blocks/permits based on source/destination IP, port, and protocol.
- **Stateful Inspection Firewall:** Tracks active connections and determines which packets are part of which connection.
- **Proxy Firewall (Application Layer):** Intercepts all traffic between two systems and acts as a proxy.
- **Next-Generation Firewall (NGFW):** Incorporates features like deep packet inspection, intrusion prevention, and application awareness.


**14. What is port scanning and how is it used in cyber attacks?**  
Port scanning is a technique used to identify open ports and services available on a target host. Attackers use port scanning to find vulnerabilities, such as unprotected or misconfigured services, that they can exploit.

**15. What is ARP poisoning and how can it be prevented?**  
ARP poisoning is an attack where malicious ARP messages are sent onto a network, causing traffic to be misrouted (often to the attacker). Prevention techniques include:
- Using static ARP entries
- Implementing packet filtering
- Using ARP inspection features on switches
- Encrypting network traffic (e.g., VPN)

**16. What are TCP and UDP? How do they differ in security context?**  
- **TCP (Transmission Control Protocol):** Connection-oriented, reliable, guarantees delivery and order of packets.
- **UDP (User Datagram Protocol):** Connectionless, faster, but does not guarantee delivery or order.
From a security perspective, TCP is less susceptible to spoofing and more easily monitored, while UDP is used in attacks like amplification because of its lack of connection state.

**17. What is VPN and how does it ensure secure communication?**  
A VPN (Virtual Private Network) creates a secure, encrypted connection (tunnel) between a user and a network over the internet, protecting data from interception and allowing users to access resources as if they were on a local network.

**18. What is MAC flooding?**  
MAC flooding is a network attack in which a switch’s MAC address table is overloaded with fake MAC addresses. The switch then fails open, sending all traffic to all ports (broadcasting), allowing attackers to capture sensitive data.

**19. How do you secure a Wi-Fi network?**  
- Use strong WPA3 or WPA2 encryption
- Change default SSID and admin credentials
- Disable WPS
- Use strong passwords
- Enable network segmentation (guest networks)
- Regularly update firmware
- Limit DHCP range and MAC address filtering

**20. What are the roles of SSL/TLS in network security?**  
SSL (Secure Sockets Layer) and TLS (Transport Layer Security) are protocols that encrypt data transmitted over networks, ensuring confidentiality, integrity, and authentication of data between clients and servers (e.g., HTTPS for websites).

**21. What is OS hardening? Name a few techniques.**  
OS hardening is the process of securing an operating system by reducing its surface of vulnerability. Techniques include:
- Disabling unnecessary services and ports
- Applying security patches
- Enforcing strong password policies
- Using firewalls
- Setting proper file permissions
- Removing unused user accounts

**22. What is a rootkit and how does it work?**  
A rootkit is malicious software designed to hide the existence of certain processes or programs from normal detection methods, allowing continued privileged access to a system. It works by modifying system files and kernel modules to intercept and alter standard OS behaviors.

**23. What is patch management and why is it important?**  
Patch management is the process of applying updates (patches) to software, OS, and applications to fix vulnerabilities, bugs, and improve functionality. It’s important because it helps prevent exploitation of known security flaws, reducing risk of attacks.

**24. How do you secure a Linux server?**  
- Keep system and software updated
- Use strong, unique passwords and SSH keys
- Disable root login over SSH
- Configure firewalls (e.g., iptables, ufw)
- Regularly audit logs and monitor for anomalies
- Restrict user privileges
- Disable unused services
- Use security tools like SELinux or AppArmor

**25. What is privilege escalation and how can it be prevented?**  
Privilege escalation is an attack where a user gains higher access rights than intended, often exploiting vulnerabilities. Prevention includes:
- Applying patches promptly
- Using least privilege principles
- Monitoring and auditing account activities
- Restricting access to sensitive files and binaries

**26. What are some tools to monitor system logs and detect anomalies?**  
- **Linux:** Syslog, Logwatch, Auditd, OSSEC, Splunk, ELK Stack (Elasticsearch, Logstash, Kibana)
- **Windows:** Event Viewer, Splunk, OSSEC, SolarWinds, Graylog

**27. What is the Windows Security Event Log and what are key events to monitor?**  
The Windows Security Event Log records security-related events like logons, access attempts, policy changes, and more. Key events to monitor include:
- Logon failures (Event IDs: 4625)
- Account lockouts (4740)
- Privilege use (4672)
- Object access (4663)
- Changes to audit policies (4719)
- User account changes (4720, 4722, 4723)

**28. What are secure coding practices to prevent vulnerabilities?**  
- Validate and sanitize all user inputs
- Use parameterized queries for database access
- Avoid hardcoded secrets
- Handle errors and exceptions safely
- Use secure libraries and frameworks
- Regular code reviews and static analysis
- Apply the principle of least privilege

**29. What is sandboxing in cybersecurity?**  
Sandboxing is isolating applications or processes in a restricted environment where they can run without affecting other system components. It’s used to safely execute untrusted code, analyze malware, and reduce the impact of an attack.

**30. How would you protect an application from SQL Injection?**  
- Use parameterized queries or prepared statements
- Employ input validation and sanitization
- Limit database privileges for application accounts
- Use stored procedures (with caution)
- Regularly test and scan for vulnerabilities
Here are clear, concise answers to your cybersecurity questions:

**31. What is a zero-day vulnerability?**  
A zero-day vulnerability is a software flaw that is unknown to the vendor and has no official fix. Attackers can exploit it before developers are aware and can patch it, making it highly dangerous.

**32. What is ransomware? How do you prevent it?**  
Ransomware is malware that encrypts a victim’s data and demands a ransom for decryption. Prevention includes:
- Regularly backing up data
- Using strong antivirus and endpoint protection
- Keeping software updated
- Training users to avoid suspicious links/attachments
- Applying the principle of least privilege

**33. What is a man-in-the-middle (MITM) attack?**  
A MITM attack occurs when an attacker secretly intercepts and possibly alters communication between two parties who believe they are directly communicating with each other.

**34. What is Cross-Site Scripting (XSS)?**  
XSS is a web vulnerability where attackers inject malicious scripts into trusted websites. These scripts execute in the browser of users, potentially stealing data or performing actions on their behalf.

**35. What is a buffer overflow attack?**  
A buffer overflow attack occurs when more data is written to a buffer (memory location) than it can hold, overwriting adjacent memory and potentially allowing attackers to execute malicious code.

**36. What are DDoS attacks and how can they be mitigated?**  
Distributed Denial of Service (DDoS) attacks overwhelm a target (website, server, etc.) with excessive traffic from multiple sources, making it unavailable. Mitigation strategies include:
- Using DDoS protection services (Cloudflare, Akamai)
- Implementing rate limiting and filtering
- Scaling infrastructure
- Monitoring network traffic for anomalies
  
**37. What is phishing and how do you defend against it?**  
Phishing is a social engineering attack where attackers trick users into revealing sensitive information (like passwords) via fake emails, websites, or messages. Defense includes:
- User education and awareness
- Email filtering and anti-phishing tools
- Verifying suspicious communications
- Using multifactor authentication

**38. What is session hijacking?**  
Session hijacking is an attack where an attacker steals or predicts a valid session token, allowing them to impersonate a user and gain unauthorized access to a system.

**39. What is a botnet?**  
A botnet is a network of compromised computers (bots) controlled remotely by an attacker, often used for launching DDoS attacks, spreading malware, or mining cryptocurrency.

**40. What are common indicators of compromise (IoCs)?**  
IoCs are signs that a system or network may have been breached. Common IoCs include:
- Unusual outbound network traffic
- Unexpected changes in system files or configurations
- Unknown processes or software
- Multiple failed login attempts
- Alerts from security tools
- Suspicious account activity

**41.What are the top OWASP vulnerabilities?**
Top OWASP Vulnerabilities (OWASP Top 10 2021):

The OWASP Top 10 is a standard awareness document listing the most critical security risks to web applications. As of the 2021 update, the top vulnerabilities are:
-Broken Access Control – Failure to restrict user access to resources or functions.
-Cryptographic Failures – Weak or improper use of cryptography, leading to exposure of sensitive data.
-Injection – Unsanitized input leading to injection attacks (e.g., SQL, NoSQL, Command Injection).
-Insecure Design – Inadequate security controls due to poor design decisions.
-Security Misconfiguration – Incorrectly configured security settings or lack of hardening.
-Vulnerable and Outdated Components – Using components with known vulnerabilities.
-Identification and Authentication Failures – Broken authentication mechanisms allowing attackers to compromise credentials or sessions.
-Software and Data Integrity Failures – Failing to verify code or data integrity (e.g., using untrusted plugins).
-Security Logging and Monitoring Failures – Lack of proper logging and monitoring to detect and respond to attacks.
-Server-Side Request Forgery (SSRF) – Attackers trick the server into making requests to unintended locations.
-Reference: OWASP Top 10 (2021)

**42. What is penetration testing? How is it different from vulnerability scanning?**  
Penetration testing (pentesting) is a simulated cyberattack on a system to identify and exploit vulnerabilities, testing the system’s defenses in a real-world scenario. Vulnerability scanning, on the other hand, is an automated process that identifies potential vulnerabilities but does not exploit them. Pentesting is manual, in-depth, and mimics actual attacker behavior, while vulnerability scanning is automated and preliminary.

**43. What tools do you use for penetration testing?**  
Common penetration testing tools include:
- **Metasploit Framework**
- **Nmap**
- **Burp Suite**
- **Nessus**
- **Wireshark**
- **Nikto**
- **John the Ripper**
- **Hydra**
- **Aircrack-ng**
- **sqlmap**

**44. What is Wireshark and how is it used in cybersecurity?**  
Wireshark is a network protocol analyzer that captures and displays packet data on a network in real-time. It’s used for troubleshooting network issues, analyzing traffic, detecting suspicious activity, and investigating security incidents.

**45. What is Metasploit and how does it work?**  
Metasploit is a penetration testing framework that provides tools and exploits for testing system vulnerabilities. It works by allowing testers to launch exploits against targets, automate attacks, and validate security defenses. It’s also widely used for developing and sharing attack methods.

**46. What is Nmap and what are its common use cases?**  
Nmap (Network Mapper) is a network scanning tool used to discover hosts and services on a network. Common use cases include:
- Network inventory
- Port scanning
- Service/version detection
- Vulnerability scanning
- OS fingerprinting

**47. What is the difference between static and dynamic code analysis?**  
- **Static code analysis** reviews source code or binaries without executing them, identifying vulnerabilities, coding errors, and policy violations.
- **Dynamic code analysis** examines the behavior of running applications, finding runtime errors and vulnerabilities that only appear during execution.

**48. What is a security information and event management (SIEM) system?**  
A SIEM system aggregates, analyzes, and correlates security data from multiple sources (logs, events, alerts) in real-time to detect threats, support incident response, and ensure compliance.

**49. What is threat hunting?**  
Threat hunting is a proactive process where security professionals search for hidden threats or malicious activity within an environment, rather than relying solely on automated detection tools.

**50. What’s the purpose of an incident response plan?**  
An incident response plan provides structured procedures for detecting, responding to, and recovering from cybersecurity incidents. Its purpose is to minimize damage, reduce recovery time, and ensure business continuity.
