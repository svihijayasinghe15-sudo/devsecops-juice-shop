/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'path'
import { Request, Response, NextFunction } from 'express'

const challengeUtils = require('../lib/challengeUtils')
const security = require('../lib/insecurity')
const challenges = require('../data/datacache').challenges

module.exports = function servePublicFiles () {
  return (req: Request, res: Response, next: NextFunction) => {
    const file = req.params.file

    if (file && !file.includes('/')) {
      verify(file, res, next)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }

  function verify (file: string, res: Response, next: NextFunction) {
    // FIX: Strip poison null bytes BEFORE validating file extension
    const sanitizedFile = security.cutOffPoisonNullByte(file)

    if (sanitizedFile && (endsWithAllowlistedFileType(sanitizedFile) || (sanitizedFile === 'incident-support.kdbx'))) {
      challengeUtils.solveIf(challenges.directoryListingChallenge, () => { return sanitizedFile.toLowerCase() === 'acquisitions.md' })
      verifySuccessfulPoisonNullByteExploit(sanitizedFile)

      // FIX: Prevent path traversal by resolving canonical path inside /ftp directory
      const basePath = path.resolve('ftp/')
      const resolvedPath = path.resolve('ftp/', sanitizedFile)

      if (resolvedPath.startsWith(basePath)) {
        res.sendFile(resolvedPath)
      } else {
        res.status(403)
        next(new Error('Access Denied: Invalid file path!'))
      }
    } else {
      res.status(403)
      next(new Error('Only .md and .pdf files are allowed!'))
    }
  }

  function verifySuccessfulPoisonNullByteExploit (file: string) {
    challengeUtils.solveIf(challenges.easterEggLevelOneChallenge, () => { return file.toLowerCase() === 'eastere.gg' })
    challengeUtils.solveIf(challenges.forgottenDevBackupChallenge, () => { return file.toLowerCase() === 'package.json.bak' })
    challengeUtils.solveIf(challenges.forgottenBackupChallenge, () => { return file.toLowerCase() === 'coupons_2013.md.bak' })
    challengeUtils.solveIf(challenges.misplacedSignatureFileChallenge, () => { return file.toLowerCase() === 'suspicious_errors.yml' })

    challengeUtils.solveIf(challenges.nullByteChallenge, () => {
      return challenges.easterEggLevelOneChallenge.solved || challenges.forgottenDevBackupChallenge.solved || challenges.forgottenBackupChallenge.solved ||
        challenges.misplacedSignatureFileChallenge.solved || file.toLowerCase() === 'encrypt.pyc'
    })
  }

  function endsWithAllowlistedFileType (param: string): boolean {
    // FIX: Use canonical path extension check
    const ext = path.extname(param).toLowerCase()
    return ext === '.md' || ext === '.pdf'
  }
}