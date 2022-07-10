import 'dotenv/config'
import buildServer from './server.js'

const config = {
  host: process.env.HOST || 'localhost',
  port: process.env.PORT || 5040,
}

const server = buildServer({
  logger: process.env.NODE_ENV === 'development',
})

server.listen(config, (error, address) => {
  if (error) {
    server.log.error(error)
    process.exit(1)
  }
  console.log(`auth-backend is listening on ${address}`)
})
