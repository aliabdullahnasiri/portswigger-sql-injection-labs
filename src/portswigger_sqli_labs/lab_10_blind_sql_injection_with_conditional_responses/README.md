# Lab 10 - Blind SQL Injection with Conditional Responses

## Overview

This lab demonstrates a **Blind SQL Injection vulnerability using conditional responses**.

Unlike normal SQL injection, the application does not directly return database errors or query results. Instead, the attacker can determine whether a SQL condition is true or false by observing differences in the application's response.

The goal of this lab is to extract the administrator user's password by using the application's response behavior as an information channel.

## Vulnerability Type

- **Category:** Blind SQL Injection
- **Technique:** Conditional Responses
- **Database Interaction:** Boolean-based inference
- **Target Data:** Administrator password

## Lab Objective

Retrieve the password of the `administrator` user and use it to authenticate.

## Attack Flow

The exploitation process:

1. Identify a vulnerable cookie parameter.
2. Inject SQL conditions into the cookie value.
3. Detect true/false responses.
4. Determine the password length.
5. Extract each password character individually.
6. Reconstruct the administrator password.

## Vulnerable Parameter

The vulnerable parameter is:

```
TrackingId cookie
```

Example:

```
Cookie: TrackingId=xyz
```

The application uses this value in a SQL query without proper sanitization.

## Tools Used

- Burp Suite
- Python 3
- Requests
- ThreadPoolExecutor
- Rich (terminal output)

## Running the Exploit

Install dependencies:

```bash
uv sync
```

Run the exploit:

```bash
uv run python exploit.py
```

The script will:

- Find the password length.
- Brute-force each character.
- Display the discovered password.

## Example Output

```
Initializing attack against target

Starting password length discovery

Password length discovered: 20

Password: 8x7a9k2m4p1q6r0s3t5z
```

## Learning Notes

Blind SQL injection does not directly expose database information.

Instead, attackers ask the database questions:

Example:

```sql
Is the password length greater than 10?
```

If the application response changes, the attacker learns the answer.

By repeating this process, sensitive data can be extracted character by character.

## Mitigation

Prevent blind SQL injection using:

- Parameterized queries
- Prepared statements
- ORM query binding
- Input validation
- Least privilege database accounts

Example:

```python
cursor.execute(
    "SELECT * FROM users WHERE username = %s",
    (username,)
)
```

## Disclaimer

This solution is created for educational purposes and only targets PortSwigger Web Security Academy labs.

Never test SQL injection techniques against systems without authorization.
