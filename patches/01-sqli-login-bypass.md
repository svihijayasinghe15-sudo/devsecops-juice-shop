# Vulnerability Cycle 1: SQL Injection (Authentication Bypass)
-**CWE:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
- **OWASP Top 10:** A03:2021 - Injection
- **Target Endpoint:** POST `/rest/user/login`
- **Vulnerable Component:** `routes/login.ts`

## 1. Vulnerability Description & Root Cause
The user authentication mechanism dynamically concatenates unsanitized user input (`req.body.email`) directly into an SQLite database query string using Sequelize raw queries.
## 2. Exploitation Walkthrough
- Payload: `' OR 1=1--`
- Password Any string ( `test123`)
-Execution:
  1. Navigate to `http://localhost:3000/#/login`.
  2. Input the payload into the Email field.
  3. Submit the form.
  4. The query evaluates to `WHERE email = '' OR 1=1-- ...`, bypassing password verification and authenticating as the first database record (`admin@juice-sh.op`).

*(Insert screenshot of successful admin login here)*
## 3. Remediation & Code Patch

### Vulnerable Implementation (Before):
```typescript
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`,
  { model: models.User }
)
```
### Remediated Implementation (After):
```javascript
models.sequelize.query(
  'SELECT * FROM Users WHERE email = :email AND password = :password AND deletedAt IS NULL',
  {
    replacements: {
      email: req.body.email || '',
      password: security.hash(req.body.password || '')
    },
    model: models.User
  }
)
```
## 4. Verification & Retest
   1.the SQLite CLI verification
   2.crete a test script called"test_sq;i.js"
```bash
sudo docker exec -it juice-shio-app/nodejs/bin/node/juice-shop/test_sqli.j
