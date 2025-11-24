require('./load-env.js')

const { readFileSync } = require('node:fs')
const { join } = require('node:path')
const { parse } = require('node:url')

const { getCognitoTokensFromCodeUrlQuery, isAuthorized } = require('./utils/cognito.js')
const WebServer = require('./WebServer.js')

const webServer = new WebServer()

const serveLandingPage = (req, res) => {
  const landingPage = readFileSync(join(__dirname, 'index.html'), 'utf8')

  res
    .writeHead(200, {
      'Content-Length': Buffer.byteLength(landingPage),
      'Content-Type': 'text/html',
    })
    .end(landingPage)
}

webServer
  .initialize()
  .addRoute('GET', '/', async (req, res) => {
    const url = parse(req.url, process.env.HOST)
    const { accessToken } = url.query

    if (!(await isAuthorized(accessToken))) {
      const message = 'Unauthorized'
      return res.writeHead(404, {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(message)
      }).end(message)
    }

    serveLandingPage(req, res)
  })
  .addRoute('GET', '/cognito', async (req, res) => {
    try {
      const { access_token } = await getCognitoTokensFromCodeUrlQuery(req, res)

      res.statusCode = 301
      res.setHeader('Location', `/?accessToken=${access_token}`)
      res.end()
    } catch (error) {
      if (error.message === 'Invalid JWT tokens') {
        return res.writeHead(404, {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(error.message)
        }).end(error.message)
      }

      console.error(error)
      
      res.writeHead(500).end()
    }
    
  })
  .listen(80)
