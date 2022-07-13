import argon2 from 'argon2'
import jwt from 'jsonwebtoken'
import cryptoRandomString from 'crypto-random-string'
import {
  getToken,
  deleteToken,
  saveToken,
  saveUser,
  getUserById,
  getUserByEmail,
} from './db.js'

const jwtSecret = process.env.JWT_SECRET || 'you-must-define-a-secret'

const loginSchema = {
  body: {
    type: 'object',
    properties: {
      email: {
        type: 'string',
        format: 'email',
      },
      password: {
        type: 'string',
        pattern: '^(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])[0-9a-zA-Z]{8,}',
      },
      username: {
        type: 'string',
        pattern: '^[a-zA-Z0-9]{3,}$',
      },
    },
    required: ['email', 'password'],
  },
  response: {
    '2xx': {
      type: 'object',
      properties: {
        accessToken: { type: 'string' },
      },
    },
  },
}

const registerOpts = { schema: loginSchema }
const loginOpts = { schema: loginSchema }

export default async function router(fastify) {
  // Common tokens middleware
  fastify.decorateReply('sendTokens', function (user) {
    const options = {
      expiresIn: process.env.ACCESS_TOKEN_TTL || '15m',
      issuer: 'https://auth.voqse.com',
    }
    const payload = {
      email: user.email,
      username: user.username,
      name: user.name,
    }

    const accessToken = jwt.sign(payload, jwtSecret, options)
    const refreshToken = cryptoRandomString({ length: 64, type: 'url-safe' })

    saveToken(user, refreshToken)

    this.setCookie('refresh_token', refreshToken, {
      httpOnly: true,
      session: false,
      path: '/',
    })
    this.send({ accessToken })
  })

  // Registration
  fastify.post('/user/new', registerOpts, async function (request, reply) {
    const { email, password, username } = request.body
    const user = await getUserByEmail(email)

    if (user) {
      reply.code(400).send({
        error: 'User already exists',
      })
    }

    let genUsername = username
    if (!username) {
      genUsername =
        email.split('@')[0] + '-' + cryptoRandomString({ length: 4 })
    }
    const passwordHash = await argon2.hash(password)
    const newUser = await saveUser({
      email,
      passwordHash,
      username: genUsername,
    })

    reply.code(201).sendTokens(newUser)
  })

  // Authentication
  fastify.post('/session/new', loginOpts, async function (request, reply) {
    const { email, password } = request.body
    const user = await getUserByEmail(email)

    if (!user) {
      reply.code(400).send({
        error: 'User does not exist',
      })
    }
    const isValid = await argon2.verify(user.passwordHash, password)

    if (!isValid) {
      reply.code(400).send({
        error: 'Password does not match',
      })
    }
    reply.code(200).sendTokens(user)
  })

  // Refresh
  fastify.post('/session', async function (request, reply) {
    const { refresh_token } = request.cookies
    const refreshToken = await getToken(refresh_token)
    const user = refreshToken && (await getUserById(refreshToken.userId))

    if (!refreshToken || !user) {
      reply.code(400).send({
        error: 'Invalid refresh token',
      })
    }
    await deleteToken(refreshToken.token)

    reply.code(200).sendTokens(user)
  })

  // Logout
  fastify.delete('/session', async function (request, reply) {
    const { refresh_token } = request.cookies
    const refreshToken = await getToken(refresh_token)

    if (!refreshToken) {
      reply.code(400).send({
        error: 'Invalid refresh token',
      })
    }
    await deleteToken(refreshToken.token)

    reply.clearCookie('refresh_token')
    reply.code(200).send()
  })
}
