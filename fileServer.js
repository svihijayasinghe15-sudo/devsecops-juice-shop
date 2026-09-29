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
    // SECURE FIX 1: Strip poison null byte BEFORE validation
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
      // SECURE FIX 2: Clean response WITHOUT Express error object stack leaks!
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