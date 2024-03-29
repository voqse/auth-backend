import fp from 'fastify-plugin'
import jwt from 'jsonwebtoken'
import cryptoRandomString from 'crypto-random-string'
import { saveToken } from '../db.js'

async function utils(fastify, options = {}) {
  const { secret } = options

  if (!secret) {
    return new Error('You must define a secret')
  }

  // Common tokens middleware
  fastify.decorateReply('sendTokens', function (user) {
    const options = {
      expiresIn: process.env.ACCESS_TOKEN_TTL || '15m',
      issuer: process.env.JWT_ISSUER || 'https://auth.example.com',
      subject: user.id,
    }
    const payload = {
      email: user.email,
      username: user.username,
      name: user.name,
    }

    const accessToken = jwt.sign(payload, secret, options)
    const refreshToken = cryptoRandomString({ length: 64, type: 'url-safe' })

    saveToken(user, refreshToken)

    this.setCookie('refresh_token', refreshToken, {
      httpOnly: true,
      session: false,
      path: '/',
    })
    return this.send({ accessToken })
  })
}

export default fp(utils)
