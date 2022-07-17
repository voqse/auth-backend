import jwt from 'jsonwebtoken'
import buildServer from '../src/server.js'
import { clearDB, connectDB, disconnectDB } from '../src/db.js'

function register(user) {
  return server.inject({
    method: 'POST',
    url: '/users/new',
    payload: user,
  })
}

function login(user) {
  return server.inject({
    method: 'POST',
    url: '/session/new',
    payload: user,
  })
}

function refresh(refreshToken) {
  return server.inject({
    method: 'POST',
    url: '/session',
    cookies: {
      refresh_token: refreshToken,
    },
  })
}

function logout(refreshToken) {
  return server.inject({
    method: 'DELETE',
    url: '/session',
    cookies: {
      refresh_token: refreshToken,
    },
  })
}

let server = buildServer()

beforeEach(async () => {
  await server.ready()
  await connectDB('mongodb://localhost:27017/test-auth-db')
})

afterEach(async () => {
  await clearDB()
  await disconnectDB()
})

afterAll(async () => {
  await server.close()
})

const users = {
  valid: {
    email: 'validuser@example.com',
    password: 'ValidPassw0rd',
  },
  wrongPassword: {
    email: 'validuser@example.com',
    password: 'ValidPassw0rd2',
  },
  invalidEmail: {
    email: 'invalid@mail',
    password: 'ValidPassw0rd',
  },
  invalidPassword: {
    email: 'validemail@example.com',
    password: 'invalid password',
  },
  nonExistent: {
    email: 'validemailbutu@example.com',
    password: 'ValidPassw0rd',
  },
}

describe('Registration', () => {
  test('User gets 201 on successful registration', async () => {
    const { statusCode, cookies, body } = await register(users.valid)
    const { accessToken } = JSON.parse(body)
    const { email } = jwt.decode(accessToken)

    expect(statusCode).toBe(201)
    expect(email).toBe(users.valid.email)
    expect(cookies[0].name).toBe('refresh_token')
    expect(cookies[0].value).toBeTruthy()
  })

  test('User gets 409 when trying to register with existing email', async () => {
    await register(users.valid)

    const { statusCode } = await register(users.valid)
    expect(statusCode).toBe(409)
  })

  test('User gets 400 when trying to register with invalid email', async () => {
    const { statusCode } = await register(users.invalidEmail)
    expect(statusCode).toBe(400)
  })

  test('User gets 400 when trying to register with invalid password', async () => {
    const { statusCode } = await register(users.invalidPassword)
    expect(statusCode).toBe(400)
  })
})

describe('Login', () => {
  test('User gets 200 on successful login && gets access and refresh tokens', async () => {
    await register(users.valid)

    const { statusCode, cookies, body } = await login(users.valid)
    const { accessToken } = JSON.parse(body)
    const { email } = jwt.decode(accessToken)

    expect(statusCode).toBe(200)
    expect(email).toBe(users.valid.email)
    expect(cookies[0].name).toBe('refresh_token')
    expect(cookies[0].value).toBeTruthy()
  })

  test('User gets 401 when trying to login with non-existent user', async () => {
    const response = await login(users.nonExistent)
    expect(response.statusCode).toBe(401)
  })

  test('User gets 401 when trying to login with incorrect password', async () => {
    const response = await login(users.wrongPassword)
    expect(response.statusCode).toBe(401)
  })

  test('User gets 400 when trying to login with invalid email', async () => {
    const response = await login(users.invalidEmail)
    expect(response.statusCode).toBe(400)
  })

  test('User gets 400 when trying to login with invalid password', async () => {
    const response = await login(users.invalidPassword)
    expect(response.statusCode).toBe(400)
  })
})

describe('Refresh', () => {
  test('User gets 200 on successful refresh && gets new access and refresh tokens', async () => {
    await register(users.valid)
    const { cookies: oldCookies } = await login(users.valid)

    const { statusCode, cookies, body } = await refresh(oldCookies[0].value)
    const { accessToken } = JSON.parse(body)
    const { email } = jwt.decode(accessToken)

    expect(statusCode).toBe(200)
    expect(email).toBe(users.valid.email)
    expect(cookies[0].name).toBe('refresh_token')
    expect(cookies[0].value).toBeTruthy()
  })

  test('User gets 401 when trying to refresh with invalid or expired refresh token', async () => {
    const { statusCode } = await refresh('invalid-token')
    expect(statusCode).toBe(401)
  })
})

describe('Logout', () => {
  test('User gets 200 on successful logout', async () => {
    await register(users.valid)
    const { cookies: oldCookies } = await login(users.valid)

    const { statusCode, cookies } = await logout(oldCookies[0].value)
    expect(statusCode).toBe(200)
    expect(cookies[0].value).toBeFalsy()
  })

  test('User gets 401 when trying to use refresh token after logout', async () => {
    await register(users.valid)
    const { cookies: oldCookies } = await login(users.valid)
    const { cookies } = await logout(oldCookies[0].value)

    const { statusCode } = await logout(cookies[0].value)
    expect(statusCode).toBe(401)
  })
})

// describe('/reset endpoint', () => {})

// TODO: Check expiration of tokens
// TODO: Make fake DB for CI tests
