# Blind SQL Injection with Conditional Errors (Oracle)

## Goal
This lab has a blind SQL injection vulnerability in a tracking cookie. The application runs a SQL query using the cookie's value, but never returns the query results or changes its response based on them. If the query causes an error, the application shows a custom error message. The database has a `users` table with `username` and `password` columns. The goal is to exploit the blind SQL injection to find the administrator's password and log in as them.

## How I knew it was blind
I put a single quote in the `TrackingId` cookie, which caused an internal error, confirming the input reaches a SQL query unsanitized. Since this is a "conditional errors" lab, a visible content change like "Welcome back" wasn't available — the only oracle is error vs no error.

My first attempt used a generic conditional-error payload: `xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END)='1`. This errored on both `1=1` and `1=2`, so it wasn't a valid oracle. I researched this and found that the `CASE WHEN ... 1/0` syntax isn't universal across databases, so I needed to identify the backend first.

## Identifying the database
I tested database-specific syntax and confirmed the backend was Oracle using: `'||(SELECT '' FROM dual)||'`

## Building the true/false oracle
With Oracle confirmed, I used its `TO_CHAR` casting to force a divide-by-zero error only when the condition is true: `TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||''`. This gave a reliable error/no-error oracle.

## Extracting the data
I checked the password length with: `xyz'||(SELECT CASE WHEN (LENGTH(password)=20) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||''`. This caused a 500 error, confirming the password is 20 characters.

I then tested each character with: `xyz'||(SELECT CASE WHEN (SUBSTR(password,1,1)='a') THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||''`, using binary search to narrow down each character instead of testing a-z one by one, since the password could contain numbers, uppercase, and special characters, not just lowercase letters.

## Automation
I wanted to automate this with Burp Intruder's Sniper mode, but that needs the Pro version and I only have Community Edition. So I wrote a Python script instead ([pentest-tools](link)), adapted from a script I'd written for an earlier message-based blind SQLi lab (where the oracle was "Welcome back" appearing or not). For this lab I changed the detection logic to check the HTTP status code instead of page content, and switched from testing characters directly to testing ASCII codes with a binary search, since the password could contain a wider character set than a-z.

## What went wrong first
My first conditional-error payload (`1/0` without `TO_CHAR` and without knowing the DB type) errored on both true and false conditions, which taught me that blind SQLi payloads are database-specific — I had to confirm the DB engine before I could build a working oracle.

## How to prevent it
Use parameterized queries (prepared statements) instead of building SQL from user input, validate input server-side, and use a database account with least-privilege access so errors can't be used to infer data.
