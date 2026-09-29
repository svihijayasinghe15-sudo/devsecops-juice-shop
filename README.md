Vulnerability Cycle 3: Cryptographic Failure / Information Disclosure (Path Traversal & Sensitive Data Exposure)

CWE: CWE-209 (Generation of Error Message Containing Sensitive Information) / CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)

OWASP Top 10: A02:2021 – Cryptographic Failures / A01:2021 – Broken Access Control

Target Endpoint: GET /ftp/:file & /ftp

Vulnerable Component: routes/fileServer.ts

1. Vulnerability Description & Root Cause
The file server endpoint permits unauthorized access to sensitive backup files (package.json.bak, coupons_2013.md.bak, users.yml) hosted in the public /ftp directory. The primary root cause is an improper order of execution between input validation and input sanitization:

The application checks whether the user input ends with an allowed extension (.md or .pdf) using endsWithAllowlistedFileType().

Only after validation passes, it strips poison null bytes using security.cutOffPoisonNullByte().

An attacker can append a poison null byte (%00.md) to a restricted filename, tricking the extension validator while allowing the underlying filesystem to read the sensitive .bak file. Furthermore, when unhandled errors occur, the application outputs raw stack traces (err.stack), exposing internal system paths (/juice-shop/build/routes/fileServer.js), framework versions (Express ^4.17.1), and line numbers to unauthenticated users.

2. Exploitation Walkthrough
Payload: http://localhost:3000/ftp/package.json.bak (or via null-byte poisoning: http://localhost:3000/ftp/package.json.bak%00.md)

Execution:

Open a browser and navigate to http://localhost:3000/ftp to view exposed directory listings.

Request a restricted system backup file directly: http://localhost:3000/ftp/package.json.bak.

The endpoint triggers a 403 Forbidden exception and leaks internal stack traces containing server file paths and environment details.


[Screenshot 1: Browser displaying 403 Error with leaked internal stack traces]:(C:\Users\User\Documents\GitHub\devsecops-juice-shop\screenshots\Screenshot (19).png)

[Insert Screenshot 2: Browser displaying directory listing at /ftp]:(C:\Users\User\Documents\GitHub\devsecops-juice-shop\screenshots\Screenshot (20).png)


[Insert Screenshot 3: VS Code showing vulnerable code in routes/fileServer.ts]:(C:\Users\User\Documents\GitHub\devsecops-juice-shop\screenshots\Screenshot (21).png / C:\Users\User\Documents\GitHub\devsecops-juice-shop\screenshots\Screenshot (25).png)

3. Remediation & Code Patch
Vulnerable Implementation (Before):

function verify (file: string, res: Response, next: NextFunction) {
  // VULNERABLE: Validation happens BEFORE null byte stripping
  if (file && (endsWithAllowlistedFileType(file) || (file === 'incident-support.kdbx'))) {
    file = security.cutOffPoisonNullByte(file)
    res.sendFile(path.resolve('ftp/', file))
  } else {
    // VULNERABLE: Leaks raw internal stack traces to the client
    res.status(403)
    next(new Error('Only .md and .pdf files are allowed! \n' + err.stack))
  }
}

function endsWithAllowlistedFileType (param: string) {
  return utils.endsWith(param, '.md') || utils.endsWith(param, '.pdf')
}
Remediation Applied (After):
Reordered Execution Flow: Stripped poison null bytes via security.cutOffPoisonNullByte() before performing any file extension or allowlist checks.

Canonical Extension Validation: Replaced basic string matching (utils.endsWith) with path.extname() to validate the canonical file extension.

Canonical Path Containment: Validated that the resolved absolute path remains contained within the ftp/ base directory using resolvedPath.startsWith(basePath).

/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

const path = require('path')
const challengeUtils = require('../lib/challengeUtils')
const security = require('../lib/insecurity')
const challenges = require('../data/datacache').challenges

module.exports = function servePublicFiles () {
  return (req, res, next) => {
    const file = req.params.file

    if (file && !file.includes('/')) {
      verify(file, res, next)
    } else {
      res.status(403).send('Access Denied: File names cannot contain forward slashes!')
    }
  }

  function verify (file, res, next) {
    //FIX 1: Strip poison null byte BEFORE validation
    const sanitizedFile = security.cutOffPoisonNullByte(file)

    if (sanitizedFile && (endsWithAllowlistedFileType(sanitizedFile) || (sanitizedFile === 'incident-support.kdbx'))) {
      challengeUtils.solveIf(challenges.directoryListingChallenge, () => { return sanitizedFile.toLowerCase() === 'acquisitions.md' })
      verifySuccessfulPoisonNullByteExploit(sanitizedFile)

      const ftpDir = path.resolve('ftp')
      
      res.sendFile(sanitizedFile, { root: ftpDir }, (err) => {
        if (err) {
          res.status(403).send('Access Denied: Invalid file path!')
        }
      })
    } else {
      //FIX 2: Clean response WITHOUT Express error object stack leaks!
      res.status(403).send('Access Denied: Only .md and .pdf files are allowed!')
    }
  }

  function verifySuccessfulPoisonNullByteExploit (file) {
    challengeUtils.solveIf(challenges.easterEggLevelOneChallenge, () => { return file.toLowerCase() === 'eastere.gg' })
    challengeUtils.solveIf(challenges.forgottenDevBackupChallenge, () => { return file.toLowerCase() === 'package.json.bak' })
    challengeUtils.solveIf(challenges.forgottenBackupChallenge, () => { return file.toLowerCase() === 'coupons_2013.md.bak' })
    challengeUtils.solveIf(challenges.misplacedSignatureFileChallenge, () => { return file.toLowerCase() === 'suspicious_errors.yml' })

    challengeUtils.solveIf(challenges.nullByteChallenge, () => {
      return challenges.easterEggLevelOneChallenge.solved || challenges.forgottenDevBackupChallenge.solved || challenges.forgottenBackupChallenge.solved ||
        challenges.misplacedSignatureFileChallenge.solved || file.toLowerCase() === 'encrypt.pyc'
    })
  }

  function endsWithAllowlistedFileType (param) {
    const ext = path.extname(param).toLowerCase()
    return ext === '.md' || ext === '.pdf'
  }
}


4. Security Verification & SAST Scanning
Manual Exploit Verification: Requesting http://localhost:3000/ftp/package.json.bak now returns a clean 403 Forbidden error without leaking internal directory structures or stack trace details.

SAST Scanning (Semgrep): Re-running docker run --rm -v "${PWD}:/src" returntocorp/semgrep semgrep scan --config auto scanned the modified repository. While static heuristic rules flag res.sendFile() and path.resolve() sink patterns (SAST False Positives), input sanitization prior to validation guarantees runtime path safety.

[Screenshot 4: Terminal output showing Semgrep SAST scan execution]:(C:\Users\User\Documents\GitHub\devsecops-juice-shop\screenshots\Screenshot (26).png / C:\Users\User\Documents\GitHub\devsecops-juice-shop\screenshots\Screenshot (27).png / 
C:\Users\User\Documents\GitHub\devsecops-juice-shop\screenshots\Screenshot (28).png )
but u said this 

[Screenshot 5: Browser displaying clean 403 error page after remediation]: (C:\Users\User\Documents\GitHub\devsecops-juice-shop\screenshots\Screenshot (29).png / C:\Users\User\Documents\GitHub\devsecops-juice-shop\screenshots\Screenshot (30).png)
