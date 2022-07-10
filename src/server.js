import fastify from 'fastify'
import cookie from '@fastify/cookie'
import router from './router.js'

const cookiesSecret = process.env.COOKIES_SECRET || 'you-must-define-a-secret'

export default function buildServer(options = {}) {
  const server = fastify(options)

  // Register middlewares
  server.register(cookie, {
    secret: cookiesSecret, // for cookies signature
    parseOptions: {}, // options for parsing cookies
  })
  server.register(router)

  return server
}
