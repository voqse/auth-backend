import argon2 from 'argon2'
import cryptoRandomString from 'crypto-random-string'
import {
  getToken,
  deleteToken,
  saveUser,
  getUserById,
  getUserByEmail,
} from './db.js'
import createError from 'http-errors'

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
  // Registration
  fastify.post('/users/new', registerOpts, async function (request, reply) {
    const { email, password, username } = request.body
    const user = await getUserByEmail(email)

    if (user) {
      throw new createError.Conflict('User already exists')
    }

    // TODO: Check if username is taken
    // TODO: Better username validation
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

    return reply.code(201).sendTokens(newUser)
  })

  // Authentication
  fastify.post('/session/new', loginOpts, async function (request, reply) {
    const { email, password } = request.body
    const user = await getUserByEmail(email)
    const isValid = user && (await argon2.verify(user.passwordHash, password))

    if (!user || !isValid) {
      throw new createError.Unauthorized('Invalid email or password')
    }
    return reply.code(200).sendTokens(user)
  })

  // Refresh
  fastify.post('/session', async function (request, reply) {
    const { refresh_token } = request.cookies
    const refreshToken = await getToken(refresh_token)
    const user = refreshToken && (await getUserById(refreshToken.userId))

    if (!refreshToken || !user) {
      throw new createError.Unauthorized('Invalid refresh token')
    }
    await deleteToken(refreshToken.token)

    return reply.code(200).sendTokens(user)
  })

  // Logout
  fastify.delete('/session', async function (request, reply) {
    const { refresh_token } = request.cookies
    const refreshToken = await getToken(refresh_token)

    if (!refreshToken) {
      throw new createError.Unauthorized('Invalid refresh token')
    }
    await deleteToken(refreshToken.token)

    reply.clearCookie('refresh_token')
    return reply.code(200).send()
  })
}
