const { createServer } = require('node:http')
const { parse } = require('node:url')

const HOST = 'localhost'

module.exports = class WebServer {
  #server = null

  initialize() {
    this.#server = createServer()
    return this
  }

  listen(port) {
    this.#server.listen(port)
    return this
  }

  addRoute(method, path, cb) {
    this.#server.on('request', (req, res) => {
      const url = parse(req.url, process.env.HOST)

      if (url.pathname !== path || req.method !== method) {
        return
      }

      cb(req, res)
    })
    return this
  }
}
