/**
 * Proof Generator Service Worker
 * Polls bridge for commands, injects cookies, captures screenshots
 */

const BRIDGE_URL = 'http://localhost:3000'
const KEEPALIVE_ALARM = 'proof-keepalive'

let currentUserAgent = null
let pollingActive = false

// CDP network capture, buffered per-navigation, keyed by requestId
let debuggee = null
const netRequests = new Map()
let cdpAttached = false

async function attachDebugger(tabId) {
  if (cdpAttached && debuggee?.tabId === tabId) return
  if (cdpAttached) await detachDebugger()
  debuggee = { tabId }
  await chrome.debugger.attach(debuggee, '1.3')
  await chrome.debugger.sendCommand(debuggee, 'Network.enable')
  cdpAttached = true
  console.log('[Proof] CDP attached to tab', tabId)
}

async function detachDebugger() {
  if (!cdpAttached) return
  try { await chrome.debugger.detach(debuggee) } catch (e) {}
  cdpAttached = false
}

function resetNetLog() {
  netRequests.clear()
}

chrome.debugger.onEvent.addListener((source, method, params) => {
  if (!debuggee || source.tabId !== debuggee.tabId) return
  if (method === 'Network.requestWillBeSent') {
    const r = params.request
    netRequests.set(params.requestId, {
      requestId: params.requestId,
      type: params.type,
      method: r.method,
      url: r.url,
      request_headers: r.headers,
      post_data: r.postData || null,
      has_post_data: !!r.hasPostData,
      timestamp: params.wallTime
    })
  } else if (method === 'Network.responseReceived') {
    const e = netRequests.get(params.requestId)
    if (e) {
      e.type = params.type
      e.status = params.response.status
      e.response_headers = params.response.headers
      e.mime_type = params.response.mimeType
    }
  } else if (method === 'Network.loadingFinished') {
    const e = netRequests.get(params.requestId)
    if (e) e.finished = true
  }
})

async function fetchBodies() {
  const out = []
  for (const e of netRequests.values()) {
    const wantBody = e.type === 'XHR' || e.type === 'Fetch' ||
      (e.mime_type && (e.mime_type.includes('json') || e.mime_type.includes('javascript')))
    if (wantBody && e.finished) {
      try {
        const b = await chrome.debugger.sendCommand(debuggee, 'Network.getResponseBody', { requestId: e.requestId })
        e.response_body = b.base64Encoded ? '[base64]' + b.body : b.body
      } catch (err) {
        e.response_body_error = err.message
      }
    }
    out.push(e)
  }
  return out
}

console.log('[Proof] Service worker starting...')

// Poll bridge for commands
async function pollOnce() {
  try {
    const res = await fetch(`${BRIDGE_URL}/api/commands`)
    if (res.ok) {
      const commands = await res.json()
      for (const cmd of commands) {
        console.log('[Proof] Command:', cmd.tool)
        await executeCommand(cmd)
      }
    }
  } catch (e) {
    // Bridge not ready, ignore
  }
}

async function startPolling() {
  if (pollingActive) return
  pollingActive = true
  console.log('[Proof] Starting bridge polling...')

  const deadline = Date.now() + 25000
  while (pollingActive && Date.now() < deadline) {
    await pollOnce()
    await new Promise(r => setTimeout(r, 100))
  }
  pollingActive = false
  setTimeout(() => startPolling(), 0)
}

// Keepalive alarm
chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === KEEPALIVE_ALARM) startPolling()
})
chrome.alarms.create(KEEPALIVE_ALARM, { periodInMinutes: 0.4 })

// Execute command and send response
async function executeCommand(cmd) {
  let result = null, success = true, error = ''

  try {
    switch (cmd.tool) {
      case 'injectSession':
        result = await injectSession(cmd.args)
        break
      case 'navigate':
        result = await navigate(cmd.args)
        break
      case 'screenshot':
        result = await screenshot()
        break
      case 'captureProof':
        result = await captureProof()
        break
      case 'eval':
        result = await evalScript(cmd.args)
        break
      case 'captureTrace':
        result = await captureTrace()
        break
      case 'getLoggedInUser':
        result = await getLoggedInUser(cmd.args?.tabId)
        break
      default:
        throw new Error(`Unknown command: ${cmd.tool}`)
    }
  } catch (e) {
    success = false
    error = e.message
  }

  // Send response
  try {
    await fetch(`${BRIDGE_URL}/api/responses`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: cmd.id, success, result, error })
    })
  } catch (e) {
    console.error('[Proof] Failed to send response:', e)
  }
}

// Inject cookies and set user agent
async function injectSession({ cookies, userAgent }) {
  console.log('[Proof] Injecting session:', cookies?.length, 'cookies')

  // Inject cookies
  let set = 0, failed = 0
  if (cookies?.length) {
    // chrome.cookies.set only accepts these sameSite values; "None"/"Strict"/"Lax"
    // (the standard Set-Cookie spellings) are INVALID and reject the whole cookie.
    const SS = { none: 'no_restriction', no_restriction: 'no_restriction', lax: 'lax', strict: 'strict', unspecified: 'unspecified' }
    for (const cookie of cookies) {
      try {
        const url = `http${cookie.secure ? 's' : ''}://${cookie.domain.replace(/^\./, '')}${cookie.path || '/'}`
        const secure = !!cookie.secure
        let sameSite = SS[String(cookie.sameSite || '').toLowerCase()] || 'lax'
        if (sameSite === 'no_restriction' && !secure) sameSite = 'lax' // Chrome rejects SameSite=None without Secure
        await chrome.cookies.set({
          url,
          name: cookie.name,
          value: cookie.value,
          domain: cookie.domain,
          path: cookie.path || '/',
          secure,
          httpOnly: !!cookie.httpOnly,
          sameSite,
          expirationDate: cookie.expirationDate || cookie.expires || (Date.now() / 1000 + 86400)
        })
        set++
      } catch (e) {
        failed++
        console.warn('[Proof] Failed to set cookie:', cookie.name, e.message)
      }
    }
    console.log(`[Proof] cookies set ${set}, failed ${failed}`)
  }

  // Set user agent via declarativeNetRequest
  if (userAgent) {
    currentUserAgent = userAgent
    await updateUserAgentRule(userAgent)
  }

  return { cookiesSet: set, cookiesFailed: failed, userAgent: !!userAgent }
}

// Update UA spoofing rule
async function updateUserAgentRule(userAgent) {
  const ruleId = 1

  // Remove existing rule
  try {
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: [ruleId]
    })
  } catch (e) {}

  // Add new rule
  await chrome.declarativeNetRequest.updateDynamicRules({
    addRules: [{
      id: ruleId,
      priority: 1,
      action: {
        type: 'modifyHeaders',
        requestHeaders: [{
          header: 'User-Agent',
          operation: 'set',
          value: userAgent
        }]
      },
      condition: {
        urlFilter: '*',
        resourceTypes: ['main_frame', 'sub_frame', 'xmlhttprequest', 'script', 'image', 'stylesheet', 'font', 'other']
      }
    }]
  })
  console.log('[Proof] UA rule set:', userAgent.slice(0, 50))
}

// Navigate to URL
function waitForComplete(tabId, timeout = 15000) {
  return new Promise(resolve => {
    const listener = (id, info) => {
      if (id === tabId && info.status === 'complete') {
        chrome.tabs.onUpdated.removeListener(listener)
        resolve()
      }
    }
    chrome.tabs.onUpdated.addListener(listener)
    setTimeout(resolve, timeout)
  })
}

async function navigate({ url }) {
  console.log('[Proof] Navigating to:', url)
  let [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
  if (!tab) tab = await chrome.tabs.create({ url: 'about:blank' })

  // Debugger can't attach to chrome:// pages — route through about:blank first
  if (!tab.url || tab.url.startsWith('chrome:') || tab.url.startsWith('chrome-extension:')) {
    await chrome.tabs.update(tab.id, { url: 'about:blank' })
    await waitForComplete(tab.id, 5000)
  }

  await attachDebugger(tab.id)
  resetNetLog()
  await chrome.tabs.update(tab.id, { url })
  await waitForComplete(tab.id)
  // settle: let late XHR/fetch (e.g. gql/svc) land in the buffer
  await new Promise(r => setTimeout(r, 3000))

  return { success: true, url, capturedRequests: netRequests.size }
}

// Take screenshot
async function screenshot() {
  const dataUrl = await chrome.tabs.captureVisibleTab({ format: 'png' })
  return { screenshot: dataUrl }
}

// Capture full proof
async function captureProof() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })

  // Screenshot
  const dataUrl = await chrome.tabs.captureVisibleTab({ format: 'png' })

  // Get page info via content script
  let pageInfo = {}
  if (tab?.id) {
    try {
      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => ({
          title: document.title,
          url: window.location.href,
          bodyText: document.body?.innerText?.slice(0, 10000)
        })
      })
      pageInfo = results[0]?.result || {}
    } catch (e) {
      console.warn('[Proof] Failed to get page info:', e)
    }
  }

  return {
    screenshot: dataUrl,
    url: tab?.url,
    title: tab?.title,
    pageInfo
  }
}

// Capture full trace: screenshot + rendered DOM + network log (with bodies)
async function captureTrace() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
  if (!tab?.id) throw new Error('No active tab')

  const screenshot = await chrome.tabs.captureVisibleTab({ format: 'png' })

  const domResults = await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: () => document.documentElement.outerHTML
  })
  const dom_html = domResults[0]?.result || ''

  const network_log = await fetchBodies()

  return { screenshot, dom_html, url: tab.url, title: tab.title, network_log }
}

// Get logged-in user from Twitter's authenticated page
async function getLoggedInUser(tabId) {
  if (!tabId) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
    tabId = tab?.id
  }
  if (!tabId) return { error: 'No active tab' }

  // Navigate to Twitter home
  await chrome.tabs.update(tabId, { url: 'https://x.com/home' })

  // Wait for navigation
  await new Promise(resolve => {
    const listener = (id, info) => {
      if (id === tabId && info.status === 'complete') {
        chrome.tabs.onUpdated.removeListener(listener)
        resolve()
      }
    }
    chrome.tabs.onUpdated.addListener(listener)
    setTimeout(resolve, 10000)
  })

  // Wait a bit more for API calls
  await new Promise(r => setTimeout(r, 3000))

  // Extract logged-in user from profile link (Twitter's own test ID, stable)
  const results = await chrome.scripting.executeScript({
    target: { tabId },
    func: () => {
      const profileLink = document.querySelector('a[data-testid="AppTabBar_Profile_Link"]')
      if (!profileLink) throw new Error('Profile link not found - user may not be logged in')

      const href = profileLink.getAttribute('href')
      const match = href?.match(/^\/([^/]+)$/)
      if (!match) throw new Error('Could not parse profile link href: ' + href)

      return { screen_name: match[1] }
    }
  })

  return results[0]?.result || { error: 'Script execution failed' }
}

// Extract structured data from page — returns full body text + JSON if available
async function evalScript({ script }) {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
  if (!tab?.id) throw new Error('No active tab')

  const results = await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: () => {
      const text = document.body?.innerText || ''
      // Try parsing as JSON (e.g. Reddit /about.json endpoints)
      try { return { json: JSON.parse(text), text: text.slice(0, 500) } } catch {}
      return { text, title: document.title, url: window.location.href }
    }
  })
  return results[0]?.result
}

// Start polling immediately
startPolling()

console.log('[Proof] Service worker ready')
