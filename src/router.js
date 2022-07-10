import argon2 from 'argon2'
import jwt from 'jsonwebtoken'
import cryptoRandomString from 'crypto-random-string'
import { addToken, addUser, getToken, getUser, removeToken } from './db.js'

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
  fastify.decorateReply('issueTokens', async function ({ email }) {
    const accessToken = await jwt.sign({ email }, jwtSecret)
    const refreshToken = cryptoRandomString({ length: 128, type: 'url-safe' })

    await addToken(email, refreshToken)
    this.setCookie('refresh_token', refreshToken, {
      httpOnly: true,
      session: false,
    })
    this.send({ accessToken })
  })

  // Registration
  fastify.post('/user/new', registerOpts, async function (request, reply) {
    const { email, password } = request.body
    const user = await getUser(email)

    if (user) {
      reply.code(400).send({
        error: 'User already exists',
      })
    }

    const passwordHash = await argon2.hash(password)
    const newUser = { email, password: passwordHash }

    await addUser(newUser)
    reply.code(201).issueTokens(newUser)
  })

  // Authentication
  fastify.post('/session/new', loginOpts, async function (request, reply) {
    const { email, password } = request.body
    const user = await getUser(email)

    if (!user) {
      reply.code(400).send({
        error: 'User does not exist',
      })
    }

    const isValid = await argon2.verify(user.password, password)
    if (!isValid) {
      reply.code(400).send({
        error: 'Password does not match',
      })
    }
    reply.code(200).issueTokens(user)
  })

  // Refresh
  fastify.post('/session', async function (request, reply) {
    const { refresh_token } = request.cookies
    const oldRefreshToken = await getToken(refresh_token)

    if (!oldRefreshToken) {
      reply.code(400).send({
        error: 'Invalid refresh token',
      })
    }
    await removeToken(oldRefreshToken.token)
    reply.code(200).issueTokens({ email: oldRefreshToken.email })
  })

  // Logout
  fastify.delete('/session', async function (request, reply) {
    const { refresh_token } = request.cookies
    const oldRefreshToken = await getToken(refresh_token)

    if (!oldRefreshToken) {
      reply.code(400).send({
        error: 'Invalid refresh token',
      })
    }
    await removeToken(oldRefreshToken.token)

    reply.clearCookie('refresh_token')
    reply.code(200).send()
  })
}
