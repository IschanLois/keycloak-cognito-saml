require('./load-env.js')

const { readFileSync } = require('node:fs')
const { join } = require('node:path')
const { parse } = require('node:url')
const { createPublicKey, createVerify } = require('node:crypto')
const jwt = require('jsonwebtoken')

const WebServer = require('./WebServer.js')

const webServer = new WebServer()

const COGNITO_WELL_KNOWN_URL = 'https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_iOhoo0gxf/.well-known/jwks.json'

const serveLandingPage = (req, res) => {
  const landingPage = readFileSync(join(__dirname, 'index.html'), 'utf8')

  res
    .writeHead(200, {
      'Content-Length': Buffer.byteLength(landingPage),
      'Content-Type': 'text/html',
    })
    .end(landingPage)
}

const getCognitoTokensFromCodeUrlQuery = async (req, res) => {
  const url = parse(req.url, process.env.HOST)
  const cognitoCode = getCognitoLoginCode(url)
  const [tokens, jwksResponse] = await Promise.all([
    fetchCognitoTokens(cognitoCode),
    fetchCognitoJsonWebKeys(),
  ])
  const { keys: jwks } = jwksResponse

  if (!verifyCognitoTokens(tokens, jwks)) {
    throw new Error('Invalid JWT tokens')
  }

  return tokens
}

const fetchCognitoJsonWebKeys = async () => {
  return fetch(COGNITO_WELL_KNOWN_URL, { method: 'GET'})
    .then((res) => res.json())
}

const getCognitoLoginCode = (url) => {
  if ('code' in url.query) {
    return url.query.code
  }

  return ''
}

const fetchCognitoTokens = (cognitoCode) => {
  return fetch(`${process.env.COGNITO_HOST}/oauth2/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      'grant_type': 'authorization_code',
      'code': cognitoCode,
      'client_id': process.env.COGNITO_CLIENT_ID,
      'client_secret': process.env.COGNITO_CLIENT_SECRET,
      'redirect_uri': 'http://localhost/cognito'
    })
  }).then((response) => response.json())
}

const verifyCognitoTokens = (tokens, jwks) => {
  const idToken = jwt.decode(tokens.id_token, { complete: true })
  const accessToken = jwt.decode(tokens.access_token, { complete: true })

  const idTokenJwk = findJwtJwk(jwks, idToken)
  const accessTokenJwk = findJwtJwk(jwks, accessToken)

  return verifyJwtToken(tokens.access_token, accessTokenJwk)
    && verifyJwtToken(tokens.id_token, idTokenJwk)
}

const isAuthorized = async (accessToken) => {
  const { keys: jwks } = await fetchCognitoJsonWebKeys()
  const decodeToken = jwt.decode(accessToken, { complete: true })
  const jwk = findJwtJwk(jwks, decodeToken)

  return verifyJwtToken(accessToken, jwk)
}

const findJwtJwk = (jwks, token) => {
  return jwks.find(({ kid }) => kid === token.header.kid)
}

const verifyJwtToken = (rawToken, jwk) => {
  const publicKey = createPublicKeyFromJwk(jwk)

  const [header, payload, signature] = rawToken.split('.')

  return createVerify(getAlgorithmFromJwk(jwk))
    .update(`${header}.${payload}`)
    .verify(publicKey, Buffer.from(signature, 'base64url'), 'base64url')
}

const createPublicKeyFromJwk = (jwk) => {
  return createPublicKey({
    format: 'jwk',
    key: {
      kty: jwk.kty,
      n: jwk.n,
      e: jwk.e,
    }
  })
} 

const getAlgorithmFromJwk = (jwk) => {
  switch (jwk.alg) {
    case 'RS256':
      return 'RSA-SHA256'
    default:
      return ''
  }
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
