# PortSwigger SQL Injection Labs

A collection of solutions, notes, and learning materials for **PortSwigger Web Security Academy SQL Injection labs**.

This repository documents practical SQL injection techniques, exploitation methods, payload development, and security concepts learned while solving real-world web security challenges.

## About This Repository

SQL Injection is one of the most common web application vulnerabilities. It happens when an application uses unsafe user input in database queries, allowing attackers to manipulate SQL statements.

The purpose of this repository is to:

- Practice SQL injection techniques in a legal and controlled environment.
- Document different attack methods and payloads.
- Build a personal reference for web application security testing.
- Improve skills for penetration testing and bug bounty hunting.

## Labs Covered

This repository will include solutions for:

- SQL injection vulnerability in `WHERE` clauses
- SQL injection allowing login bypass
- Retrieving hidden data
- UNION-based SQL injection
- Blind SQL injection
- Boolean-based blind SQL injection
- Time-based blind SQL injection
- Out-of-band SQL injection
- Database fingerprinting
- Extracting sensitive information
- SQL injection prevention techniques

## Learning Resources

The labs are based on:

- PortSwigger Web Security Academy
- SQL injection vulnerability research
- Web application penetration testing methodologies

## Tools Used

- Burp Suite
- Browser Developer Tools
- SQL knowledge
- Python scripting
- Linux command-line tools

## Example SQL Injection Payloads

> These examples are for educational purposes only and should only be used against authorized applications.

Authentication bypass example:

```sql
' OR 1=1 --
```

Checking database behavior:

```sql
' AND 1=1 --
```

Testing error-based injection:

```sql
' AND 1=CAST((SELECT version()) AS int) --
```

## Mitigation Techniques

Developers can prevent SQL injection by using:

- Parameterized queries
- Prepared statements
- ORM query builders
- Input validation
- Proper database permissions
- Avoiding dynamic SQL construction

Example:

```python
cursor.execute(
    "SELECT * FROM users WHERE username = %s",
    (username,)
)
```

## Disclaimer

This repository is created for **educational and ethical security research purposes only**.

Do not use these techniques against systems without proper authorization. Unauthorized testing of systems may be illegal.

## Author

Created as part of my cybersecurity learning journey, focusing on:

- Web Application Security
- Penetration Testing
- Vulnerability Research
- Bug Bounty Methodology
