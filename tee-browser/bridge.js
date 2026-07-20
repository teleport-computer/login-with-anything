#!/usr/bin/env node
/**
 * Proof Bridge Server
 *
 * Runs inside container, exposes HTTP API for:
 * - Cookie injection
 * - User agent setting
 * - Proof capture commands
 * - Screenshot/artifact retrieval
 */

const http = require('http')
const fs = require('fs')
const path = require('path')

const PORT = process.env.BRIDGE_PORT || 3000
// The extension's command channel listens HERE, bound to loopback only, and is deliberately not
// served on PORT. Source-IP checks cannot separate "inside the container" from "the internet"
// on every topology (see BRIDGE_TRUST_LOCAL below), but a socket bound to 127.0.0.1 that no
// gateway maps is unreachable from outside no matter what an attacker claims to be.
const INTERNAL_PORT = process.env.BRIDGE_INTERNAL_PORT || 3001
const ARTIFACTS_DIR = '/tmp/proof-artifacts'

// Ensure artifacts dir exists
if (!fs.existsSync(ARTIFACTS_DIR)) fs.mkdirSync(ARTIFACTS_DIR, { recursive: true })

// State
let currentSession = null
const commandQueue = []
const pendingCommands = new Map()

// --- Auth. The bridge is reachable over the public gateway, so every control endpoint
// (/session, /navigate, /eval, /screenshot, …) requires a shared secret that only the OAuth3 pod
// knows. Fail closed: if BRIDGE_SECRET is unset, control endpoints refuse rather than run wide
// open. The extension's polling channel is not served here at all — it has its own loopback-only
// listener on INTERNAL_PORT.
const BRIDGE_SECRET = process.env.BRIDGE_SECRET || ''
function isLoopback(req) {
  const a = req.socket.remoteAddress || ''
  return a === '127.0.0.1' || a === '::1' || a === '::ffff:127.0.0.1'
}
// Trusting the SOURCE IP is only sound where external traffic cannot arrive wearing one. On the
// Phala CVM it cannot: gateway traffic is SNAT'd to a docker-bridge address, so the private
// lwa-net (17.100.0.0/16) genuinely means "same CVM". Behind the dstack daemon it CAN: that proxy
// reaches the container over loopback, so every request from the internet arrives as 127.0.0.1,
// this check returned true for all of them, and fail-closed silently became fail-open. Same code,
// opposite security property, decided entirely by deployment topology — so it is now OFF unless a
// deployment explicitly asserts its network makes the check meaningful.
const TRUST_LOCAL = process.env.BRIDGE_TRUST_LOCAL === '1'
function isInternal(req) {
  if (!TRUST_LOCAL) return false
  const a = (req.socket.remoteAddress || '').replace('::ffff:', '')
  return isLoopback(req) || a.startsWith('17.100.')
}
function bearerOk(req) {
  return !!BRIDGE_SECRET && (req.headers['authorization'] || '') === `Bearer ${BRIDGE_SECRET}`
}

const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')

  if (req.method === 'OPTIONS') {
    res.writeHead(204)
    res.end()
    return
  }

  const url = new URL(req.url, `http://localhost:${PORT}`)

  // Health check — liveness only, no session details, no auth.
  if (url.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ status: 'ok' }))
    return
  }

  // --- auth gate ---
  // The extension channel is served ONLY by the loopback-bound internal listener. Refusing it
  // here means that even if this port is exposed, the command queue cannot be read or answered
  // from outside — previously a loopback-looking proxy could poll and inject on it freely.
  if (req.socket.localPort != INTERNAL_PORT &&
      (url.pathname === '/api/commands' || url.pathname === '/api/responses')) {
    res.writeHead(404, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ error: 'not found' }))
    return
  }
  if (url.pathname === '/api/commands' || url.pathname === '/api/responses') {
    // internal extension polling channel — localhost only
    if (!isLoopback(req)) {
      res.writeHead(403, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'forbidden (loopback only)' }))
      return
    }
  } else if (!isInternal(req)) {
    // external control endpoints require the shared secret (fail closed if unset).
    // Same-CVM (lwa-net) + loopback callers are trusted and skip it.
    if (!BRIDGE_SECRET) {
      res.writeHead(503, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'BRIDGE_SECRET not configured' }))
      return
    }
    if (!bearerOk(req)) {
      res.writeHead(401, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'unauthorized' }))
      return
    }
  }

  // Extension polls for commands
  if (url.pathname === '/api/commands' && req.method === 'GET') {
    const commands = commandQueue.splice(0, commandQueue.length)
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify(commands))
    return
  }

  // Extension posts responses
  if (url.pathname === '/api/responses' && req.method === 'POST') {
    const body = await readBody(req)
    try {
      const response = JSON.parse(body)
      console.log('[Bridge] Response:', response.id, response.success ? 'ok' : 'error')

      const pending = pendingCommands.get(response.id)
      if (pending) {
        pending.resolve(response)
        pendingCommands.delete(response.id)
      }

      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: true }))
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: e.message }))
    }
    return
  }

  // Start session with cookies + UA
  if (url.pathname === '/session' && req.method === 'POST') {
    const body = await readBody(req)
    try {
      const { cookies, userAgent } = JSON.parse(body)
      currentSession = { cookies, userAgent, startedAt: Date.now() }

      // Queue commands to inject cookies and set UA
      const result = await sendCommand('injectSession', { cookies, userAgent })

      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ success: true, session: { cookieCount: cookies?.length, userAgent: userAgent?.slice(0, 50) } }))
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: e.message }))
    }
    return
  }

  // Navigate to URL
  if (url.pathname === '/navigate' && req.method === 'POST') {
    const body = await readBody(req)
    try {
      const { url: targetUrl } = JSON.parse(body)
      const result = await sendCommand('navigate', { url: targetUrl })
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify(result))
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: e.message }))
    }
    return
  }

  // Capture proof (screenshot + page info)
  if (url.pathname === '/capture' && req.method === 'POST') {
    try {
      const result = await sendCommand('captureProof', {})

      // Save artifacts
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-')
      const artifactDir = path.join(ARTIFACTS_DIR, timestamp)
      fs.mkdirSync(artifactDir, { recursive: true })

      if (result.result?.screenshot) {
        const imgData = result.result.screenshot.replace(/^data:image\/png;base64,/, '')
        fs.writeFileSync(path.join(artifactDir, 'screenshot.png'), imgData, 'base64')
      }

      const certificate = {
        timestamp: new Date().toISOString(),
        url: result.result?.url,
        title: result.result?.title,
        session: currentSession ? { userAgent: currentSession.userAgent, cookieCount: currentSession.cookies?.length } : null,
        pageInfo: result.result?.pageInfo
      }
      fs.writeFileSync(path.join(artifactDir, 'certificate.json'), JSON.stringify(certificate, null, 2))

      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ success: true, artifactDir: timestamp, certificate }))
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: e.message }))
    }
    return
  }

  // Evaluate JavaScript in page context
  if (url.pathname === '/eval' && req.method === 'POST') {
    const body = await readBody(req)
    try {
      const { script } = JSON.parse(body)
      const result = await sendCommand('eval', { script })
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify(result.result))
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: e.message }))
    }
    return
  }

  // Get logged-in user by capturing Twitter API calls
  if (url.pathname === '/twitter/me' && req.method === 'GET') {
    try {
      const result = await sendCommand('getLoggedInUser', {}, 15000)
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify(result.result))
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: e.message }))
    }
    return
  }

  // Get screenshot directly
  if (url.pathname === '/screenshot' && req.method === 'GET') {
    try {
      const result = await sendCommand('screenshot', {})
      if (result.result?.screenshot) {
        const imgData = Buffer.from(result.result.screenshot.replace(/^data:image\/png;base64,/, ''), 'base64')
        res.writeHead(200, { 'Content-Type': 'image/png' })
        res.end(imgData)
      } else {
        res.writeHead(500, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'No screenshot' }))
      }
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: e.message }))
    }
    return
  }

  // List artifacts
  if (url.pathname === '/artifacts' && req.method === 'GET') {
    try {
      const dirs = fs.readdirSync(ARTIFACTS_DIR).filter(f => fs.statSync(path.join(ARTIFACTS_DIR, f)).isDirectory())
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ artifacts: dirs }))
    } catch (e) {
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ artifacts: [] }))
    }
    return
  }

  // Get specific artifact
  if (url.pathname.startsWith('/artifacts/') && req.method === 'GET') {
    const parts = url.pathname.split('/').filter(Boolean)
    if (parts.length >= 3) {
      const [, artifactId, filename] = parts
      const filePath = path.join(ARTIFACTS_DIR, artifactId, filename)
      if (fs.existsSync(filePath)) {
        const ext = path.extname(filename)
        const contentType = ext === '.png' ? 'image/png' : ext === '.json' ? 'application/json' : 'text/plain'
        res.writeHead(200, { 'Content-Type': contentType })
        res.end(fs.readFileSync(filePath))
        return
      }
    }
    res.writeHead(404, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ error: 'Not found' }))
    return
  }

  res.writeHead(404, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify({ error: 'Not found' }))
})

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = ''
    req.on('data', chunk => body += chunk)
    req.on('end', () => resolve(body))
    req.on('error', reject)
  })
}

let commandId = 0
function sendCommand(tool, args, timeout = 30000) {
  return new Promise((resolve, reject) => {
    const id = `cmd-${++commandId}`
    const timer = setTimeout(() => {
      pendingCommands.delete(id)
      reject(new Error(`Command ${tool} timed out`))
    }, timeout)

    pendingCommands.set(id, {
      resolve: (result) => {
        clearTimeout(timer)
        resolve(result)
      }
    })

    commandQueue.push({ id, tool, args })
    console.log('[Bridge] Queued:', tool, id)
  })
}

// Same handler, second socket: bound to 127.0.0.1 so nothing outside the container can connect,
// and it is the only listener that serves /api/commands + /api/responses. Gateways map PORT only.
const internalServer = http.createServer(server.listeners('request')[0])
internalServer.listen(INTERNAL_PORT, '127.0.0.1', () => {
  console.log(`[Bridge] Extension channel (loopback only) on 127.0.0.1:${INTERNAL_PORT}`)
})

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[Bridge] auth: secret ${BRIDGE_SECRET ? 'SET' : 'MISSING (control endpoints refuse)'}, trust-local ${TRUST_LOCAL ? 'ON' : 'off'}`)
  console.log(`[Bridge] Proof bridge listening on port ${PORT}`)
  console.log(`[Bridge] Health: http://localhost:${PORT}/health`)
  console.log(`[Bridge] Session: POST http://localhost:${PORT}/session`)
  console.log(`[Bridge] Navigate: POST http://localhost:${PORT}/navigate`)
  console.log(`[Bridge] Capture: POST http://localhost:${PORT}/capture`)
})
