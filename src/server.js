import fastify from 'fastify'
import cookie from '@fastify/cookie'
import router from './router.js'

export default function buildServer(options = {}) {
  const server = fastify(options)

  // Register middlewares
  server.register(cookie, {
    secret: process.env.COOKIES_SECRET || 'you-must-define-a-secret', // for cookies signature
    parseOptions: {}, // options for parsing cookies
  })
  server.register(router)

  return server
}
