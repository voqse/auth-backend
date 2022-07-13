import buildServer from '../src/server.js'
import jwt from 'jsonwebtoken'
import { clearDB, connectDB, disconnectDB } from '../src/db.js'

const server = buildServer()

beforeAll(async () => {
  await server.ready()
  await connectDB('mongodb://localhost:27017/test-auth-db')
})

afterAll(async () => {
  await server.close()
  await clearDB()
  await disconnectDB()
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

let testCookies

describe('/register endpoint', () => {
  test('User gets 201 on successful registration', async () => {
    const { statusCode, cookies, body } = await server.inject({
      method: 'POST',
      url: '/user/new',
      payload: users.valid,
    })
    const { accessToken } = JSON.parse(body)
    const { email } = jwt.decode(accessToken, null)

    expect(statusCode).toBe(201)
    expect(email).toBe(users.valid.email)
    expect(cookies[0].name).toBe('refresh_token')
    expect(cookies[0].value).toBeTruthy()
  })

  test('User gets 400 when trying to register with existing email', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/user/new',
      payload: users.valid,
    })
    expect(response.statusCode).toBe(400)
  })

  test('User gets 400 when trying to register with invalid email', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/user/new',
      payload: users.invalidEmail,
    })
    expect(response.statusCode).toBe(400)
  })

  test('User gets 400 when trying to register with invalid password', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/user/new',
      payload: users.invalidPassword,
    })
    expect(response.statusCode).toBe(400)
  })
})

describe('/login endpoint', () => {
  test('User gets 200 on successful login && gets access and refresh tokens', async () => {
    const { statusCode, cookies, body } = await server.inject({
      method: 'POST',
      url: '/session/new',
      payload: users.valid,
    })
    const { accessToken } = JSON.parse(body)
    const { email } = jwt.decode(accessToken, null)

    testCookies = cookies[0]

    expect(statusCode).toBe(200)
    expect(email).toBe(users.valid.email)
    expect(cookies[0].name).toBe('refresh_token')
    expect(cookies[0].value).toBeTruthy()
  })

  test('User gets 403 when trying to login with non-existent user', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/session/new',
      payload: users.nonExistent,
    })
    expect(response.statusCode).toBe(400)
  })

  test('User gets 403 when trying to login with incorrect password', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/session/new',
      payload: users.wrongPassword,
    })
    expect(response.statusCode).toBe(400)
  })

  test('User gets 403 when trying to login with invalid email', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/session/new',
      payload: users.invalidEmail,
    })
    expect(response.statusCode).toBe(400)
  })

  test('User gets 403 when trying to login with invalid password', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/session/new',
      payload: users.invalidPassword,
    })
    expect(response.statusCode).toBe(400)
  })
})

describe('/refresh endpoint', () => {
  test('User gets 200 on successful refresh && gets new access and refresh tokens', async () => {
    const { statusCode, cookies, body } = await server.inject({
      method: 'POST',
      url: '/session',
      cookies: {
        refresh_token: testCookies.value,
      },
    })
    const { accessToken } = JSON.parse(body)
    const { email } = jwt.decode(accessToken, null) //?

    testCookies = cookies[0]

    expect(statusCode).toBe(200)
    expect(email).toBe(users.valid.email)
    expect(cookies[0].name).toBe('refresh_token')
    expect(cookies[0].value).toBeTruthy()
  })

  test('User gets 400 when trying to refresh with invalid or expired refresh token', async () => {
    const { statusCode, cookies, body } = await server.inject({
      method: 'POST',
      url: '/session',
      cookies: {
        refresh_token: 'invalid token',
      },
    })
    expect(statusCode).toBe(400)
  })
})

// describe('/reset endpoint', () => {})

// TODO: Make tests independent
// TODO: Check expiration of tokens
// TODO: Make error more descriptive

describe('/logout endpoint', () => {
  test('User gets 200 on successful logout', async () => {
    const { statusCode, cookies, body } = await server.inject({
      method: 'DELETE',
      url: '/session',
      cookies: {
        refresh_token: testCookies.value,
      },
    })
    expect(statusCode).toBe(200)
    expect(cookies[0].value).toBeFalsy()
  })

  test('User gets 403 when trying to use refresh token after logout', async () => {
    const { statusCode, cookies, body } = await server.inject({
      method: 'DELETE',
      url: '/session',
      cookies: {
        refresh_token: testCookies.value,
      },
    })
    expect(statusCode).toBe(400)
  })
})
