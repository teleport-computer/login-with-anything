/**
 * Proof Generator Service Worker
 * Polls bridge for commands, injects cookies, captures screenshots
 */

const BRIDGE_URL = 'http://127.0.0.1:3001' // loopback-only channel; the public port does not serve /api/commands
const KEEPALIVE_ALARM = 'proof-keepalive'

let currentUserAgent = null
let pollingActive = false
let ourTab = null // the tab /navigate opened; /eval reads this one, never "whichever is active"

console.log('[Proof] Service worker starting...')

// Poll bridge for commands
async function pollOnce() {
  try {
    const res = await fetch(`${BRIDGE_URL}/api/commands`)
    if (res.ok) {
      const commands = await res.json()
      for (const cmd of commands) {
        if (Date.now() >= cmd.deadline) continue // the bridge already answered it as timed out
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
  let timer
  const expired = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${cmd.tool} timed out`)), cmd.deadline - Date.now())
  })
  try {
    result = await Promise.race([runCommand(cmd), expired])
  } catch (e) {
    success = false
    error = e.message
    if (Date.now() >= cmd.deadline && ourTab !== null) {
      // Abandon for real: closing the tab aborts its load and any hung executeScript in it.
      const tab = ourTab
      ourTab = null
      await chrome.tabs.remove(tab)
    }
  }
  clearTimeout(timer)

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

function runCommand(cmd) {
  switch (cmd.tool) {
    case 'injectSession': return injectSession(cmd.args)
    case 'navigate': return navigate(cmd.args)
    case 'screenshot': return screenshot()
    case 'captureProof': return captureProof()
    case 'eval': return evalScript(cmd.args)
    case 'getLoggedInUser': return getLoggedInUser(cmd.args?.tabId)
    default: throw new Error(`Unknown command: ${cmd.tool}`)
  }
}

// Inject cookies and set user agent
async function injectSession({ cookies, userAgent }) {
  console.log('[Proof] Injecting session:', cookies?.length, 'cookies')

  // Inject cookies
  if (cookies?.length) {
    for (const cookie of cookies) {
      try {
        const url = `http${cookie.secure ? 's' : ''}://${cookie.domain.replace(/^\./, '')}${cookie.path || '/'}`
        await chrome.cookies.set({
          url,
          name: cookie.name,
          value: cookie.value,
          domain: cookie.domain,
          path: cookie.path || '/',
          secure: !!cookie.secure,
          httpOnly: !!cookie.httpOnly,
          sameSite: cookie.sameSite || 'lax',
          expirationDate: cookie.expirationDate || cookie.expires || (Date.now() / 1000 + 86400)
        })
      } catch (e) {
        console.warn('[Proof] Failed to set cookie:', cookie.name, e.message)
      }
    }
  }

  // Set user agent via declarativeNetRequest
  if (userAgent) {
    currentUserAgent = userAgent
    await updateUserAgentRule(userAgent)
  }

  return { cookiesSet: cookies?.length || 0, userAgent: !!userAgent }
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
// Each navigate gets a fresh tab, so every main-frame event on it belongs to this navigation, and
// the previous tab (with anything still running in it) is closed. Resolves on this tab's load of
// the URL with the main frame's HTTP status and the tab's final URL; if the load event has not
// fired 10 s after the main-frame response, resolves with loaded: false.
async function navigate({ url }) {
  console.log('[Proof] Navigating to:', url)
  const previous = ourTab
  const tab = await chrome.tabs.create({ url: 'about:blank', active: true })
  ourTab = tab.id
  if (previous !== null) await chrome.tabs.remove(previous)
  const loading = loadOf(tab.id)
  await chrome.tabs.update(tab.id, { url })
  return { success: true, url, ...(await loading) }
}

function loadOf(tabId) {
  return new Promise((resolve, reject) => {
    const filter = { urls: ['<all_urls>'], tabId, types: ['main_frame'] }
    let response = { status: null, finalUrl: null }, started = false, settle
    const finish = (fn, value) => {
      clearTimeout(settle)
      chrome.webRequest.onCompleted.removeListener(onCompleted)
      chrome.webRequest.onErrorOccurred.removeListener(onError)
      chrome.tabs.onUpdated.removeListener(onUpdated)
      chrome.tabs.onRemoved.removeListener(onRemoved)
      fn(value)
    }
    const loaded = t => finish(resolve, { status: response.status, finalUrl: t.url, loaded: true })
    const onCompleted = d => {
      response = { status: d.statusCode, finalUrl: d.url }
      started = true
      clearTimeout(settle)
      settle = setTimeout(() => finish(resolve, { ...response, loaded: false }), 10000)
      chrome.tabs.get(tabId).then(t => { if (t.status === 'complete' && t.url !== 'about:blank') loaded(t) })
    }
    // ERR_ABORTED: the request was replaced (go.dev aborts every main-frame request and still
    // loads), so keep waiting for the tab; the command deadline bounds it. Status stays null.
    const onError = d => { if (d.error !== 'net::ERR_ABORTED') finish(reject, new Error(`${d.error} loading ${d.url}`)) }
    const onUpdated = (id, info, t) => {
      if (id !== tabId || t.url === 'about:blank') return
      if (info.status === 'loading') started = true
      if (info.status === 'complete' && started) loaded(t)
    }
    const onRemoved = id => { if (id === tabId) finish(reject, new Error('tab closed during navigation')) }
    chrome.webRequest.onCompleted.addListener(onCompleted, filter)
    chrome.webRequest.onErrorOccurred.addListener(onError, filter)
    chrome.tabs.onUpdated.addListener(onUpdated)
    chrome.tabs.onRemoved.addListener(onRemoved)
  })
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
      // Record WHY, don't return a bare {}. executeScript throws on Chromium error pages, so an
      // egress outage is indistinguishable from a genuinely empty page unless the reason survives.
      console.warn('[Proof] Failed to get page info:', e)
      pageInfo = { error: e.message }
    }
  }

  return {
    screenshot: dataUrl,
    url: tab?.url,
    title: tab?.title,
    pageInfo
  }
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
  // `script` is not run: MV3 forbids evaluating a string in the extension, so this always extracts.
  if (ourTab === null) throw new Error('No page: call /navigate first')

  const results = await chrome.scripting.executeScript({
    target: { tabId: ourTab },
    injectImmediately: true, // don't wait for document_idle, which a page still loading never reaches
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
