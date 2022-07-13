import fastify from 'fastify'
import helmet from '@fastify/helmet'
import cors from '@fastify/cors'
import cookie from '@fastify/cookie'
import router from './router.js'
import rateLimit from '@fastify/rate-limit'

export default function buildServer(options = {}) {
  const server = fastify(options)

  // Register middlewares
  // server.register(helmet)
  server.register(cors, {
    origin: /voqse\.com$/,
  })
  // server.register(rateLimit, {
  //   max: 2,
  //   timeWindow: 1000,
  // })
  server.register(cookie, {
    secret: process.env.COOKIES_SECRET || 'you-must-define-a-secret', // for cookies signature
    // parseOptions: {}, // options for parsing cookies
  })
  server.register(router)

  return server
}
