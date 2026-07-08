import JSEncrypt from 'jsencrypt';

// ==================== 路由配置 ====================
// 添加新服务只需在这里加一行
interface Route {
  path: string;        // URL 路径前缀
  port: number;        // 后端端口
  stripPath: boolean;  // 转发时是否去掉路径前缀
  rewriteTo: string;   // 去掉前缀后替换为（空=直接拼接剩余路径）
  requireAuth: boolean;// 是否需要 Worker 层认证
}

const ROUTES: Route[] = [
  { path: '/webdav/', port: 5445,  stripPath: true,  rewriteTo: '/dav/',  requireAuth: false },
  { path: '/',         port: 38521, stripPath: false, rewriteTo: '',       requireAuth: true  },
];

// ==================== 安全配置 ====================
const SESSION_COOKIE = 'uglink-session';
const SESSION_MAX_AGE = 7 * 24 * 60 * 60; // 7 天
const BLOCKED_PATHS = ['/ugreen/', '/api/ugreen/'];
const ALLOWED_METHODS = ['GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'DELETE', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK', 'PATCH'];
const HMAC_KEY_NAME = 'session-hmac-key';

// ==================== 登录页 HTML ====================
const LOGIN_PAGE = `<!DOCTYPE html>
<html lang="zh">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Access</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #f5f5f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
    .card { background: #fff; border-radius: 12px; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 320px; text-align: center; }
    h1 { font-size: 20px; color: #333; margin-bottom: 24px; }
    input { width: 100%; padding: 12px 16px; border: 1px solid #ddd; border-radius: 8px; font-size: 16px; margin-bottom: 16px; outline: none; }
    input:focus { border-color: #4a90d9; }
    button { width: 100%; padding: 12px; background: #4a90d9; color: #fff; border: none; border-radius: 8px; font-size: 16px; cursor: pointer; }
    button:hover { background: #3a7bc8; }
    .error { color: #e74c3c; font-size: 14px; margin-bottom: 12px; display: none; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Enter Password</h1>
    <div class="error" id="err">Invalid password</div>
    <form method="POST" action="/__login">
      <input type="password" name="password" placeholder="Password" autofocus required>
      <button type="submit">Login</button>
    </form>
  </div>
</body>
</html>`;

// ==================== 工具函数 ====================

async function getHmacKey(env: any): Promise<CryptoKey> {
  let keyData = await env.UGLINK_CACHE.get(HMAC_KEY_NAME);
  if (!keyData) {
    const key = await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, true, ['sign', 'verify']);
    const exported = await crypto.subtle.exportKey('raw', key);
    keyData = btoa(String.fromCharCode(...new Uint8Array(exported)));
    await env.UGLINK_CACHE.put(HMAC_KEY_NAME, keyData);
  }
  const raw = Uint8Array.from(atob(keyData), c => c.charCodeAt(0));
  return crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

async function signCookie(value: string, env: any): Promise<string> {
  const key = await getHmacKey(env);
  const data = new TextEncoder().encode(value);
  const sig = await crypto.subtle.sign('HMAC', key, data);
  return `${value}.${btoa(String.fromCharCode(...new Uint8Array(sig)))}`;
}

async function verifyCookie(signed: string, env: any): Promise<boolean> {
  const parts = signed.split('.');
  if (parts.length !== 2) return false;
  const key = await getHmacKey(env);
  const data = new TextEncoder().encode(parts[0]);
  const sig = Uint8Array.from(atob(parts[1]), c => c.charCodeAt(0));
  return crypto.subtle.verify('HMAC', key, sig, data);
}

async function isAuthenticated(request: Request, env: any): Promise<boolean> {
  // Session Cookie
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(new RegExp(`${SESSION_COOKIE}=([^;]+)`));
  if (match) {
    const signed = match[1];
    if (await verifyCookie(signed, env)) {
      const timestamp = parseInt(signed.split('.')[0], 10);
      if (!isNaN(timestamp) && Date.now() / 1000 - timestamp <= SESSION_MAX_AGE) return true;
    }
  }
  // Basic Auth
  const authHeader = request.headers.get('Authorization') || '';
  if (authHeader.startsWith('Basic ')) {
    try {
      const decoded = atob(authHeader.slice(6));
      const [, password] = decoded.split(':');
      if (password === env.ACCESS_PASSWORD) return true;
    } catch {}
  }
  return false;
}

function showLoginPage(error = false): Response {
  const html = error ? LOGIN_PAGE.replace('display: none', 'display: block') : LOGIN_PAGE;
  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

function errorResponse(msg: string): Response {
  console.error('UGLINK Worker:', msg);
  return new Response('Service temporarily unavailable', { status: 500 });
}

// ==================== uglink 认证 + 代理获取 ====================
async function getProxyForPort(port: number, env: any): Promise<{ cookie: string; origin: string } | null> {
  const cookieKey = `proxy_cookie_${port}`;
  const originKey = `proxy_origin_${port}`;

  let proxyCookie = await env.UGLINK_CACHE.get(cookieKey);
  let proxyOrigin = await env.UGLINK_CACHE.get(originKey);

  if (proxyCookie && proxyOrigin) {
    return { cookie: proxyCookie, origin: proxyOrigin };
  }

  const baseUrl = env.BASE_URL;
  const username = env.USERNAME;
  const rawPassword = env.PASSWORD;

  // 获取加密公钥
  const checkResponse = await fetch(`${baseUrl}/ugreen/v1/verify/check?token=`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username }),
  });
  if (!checkResponse.ok) return null;

  const rsaToken = checkResponse.headers.get('x-rsa-token');
  if (!rsaToken) return null;

  const encryptionPublicKey = atob(rsaToken);
  const enc1 = new JSEncrypt();
  enc1.setPublicKey(encryptionPublicKey);
  const encryptedPassword = enc1.encrypt(rawPassword);
  if (!encryptedPassword) return null;

  // 登录
  const loginResponse = await fetch(`${baseUrl}/ugreen/v1/verify/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password: encryptedPassword, keepalive: true, otp: true, is_simple: true }),
  });
  if (!loginResponse.ok) return null;

  const loginJson = await loginResponse.json();
  if (loginJson.code !== 200) return null;

  // 加密 token
  const decodedPublicKey = atob(loginJson.data.public_key);
  const enc2 = new JSEncrypt();
  enc2.setPublicKey(decodedPublicKey);
  const encryptedToken = enc2.encrypt(loginJson.data.token);
  if (!encryptedToken) return null;

  // 获取 docker token
  const tokenResponse = await fetch(`${baseUrl}/ugreen/v1/gateway/proxy/dockerToken?port=${port}`, {
    headers: {
      'X-Ugreen-Token': encryptedToken,
      'X-Ugreen-Security-Key': loginJson.data.token_id,
    },
  });
  if (!tokenResponse.ok) return null;

  const data = await tokenResponse.json();
  if (data.code !== 200) return null;

  const redirectUrl = data.data.redirect_url;

  // SSRF 防护
  if (!/\.ug(link|docker)\./.test(new URL(redirectUrl).hostname)) return null;

  const redirectResponse = await fetch(redirectUrl);
  const responseBody = await redirectResponse.text();
  const tokenMatch = responseBody.match(/ugreen-proxy-token=([^;]+)/);
  if (!tokenMatch) return null;

  proxyCookie = `ugreen-proxy-token=${tokenMatch[1]}`;
  proxyOrigin = new URL(redirectUrl).origin;

  await env.UGLINK_CACHE.put(cookieKey, proxyCookie, { expirationTtl: 3600 });
  await env.UGLINK_CACHE.put(originKey, proxyOrigin, { expirationTtl: 3600 });

  return { cookie: proxyCookie, origin: proxyOrigin };
}

// ==================== 路由匹配 ====================
function matchRoute(pathname: string): Route | null {
  for (const route of ROUTES) {
    if (route.path === '/' || pathname.startsWith(route.path)) {
      return route;
    }
  }
  return null;
}

// ==================== 主逻辑 ====================
export default {
  async fetch(request: Request, env: any, ctx: any): Promise<Response> {
    const url = new URL(request.url);

    // --- HTTP 方法限制 ---
    if (!ALLOWED_METHODS.includes(request.method)) {
      return new Response('Method not allowed', { status: 405 });
    }

    // --- 登录处理 ---
    if (url.pathname === '/__login') {
      if (request.method === 'POST') {
        const formData = await request.formData();
        const password = formData.get('password');
        if (password === env.ACCESS_PASSWORD) {
          const timestamp = Math.floor(Date.now() / 1000).toString();
          const signed = await signCookie(timestamp, env);
          return new Response(null, {
            status: 302,
            headers: {
              'Location': '/',
              'Set-Cookie': `${SESSION_COOKIE}=${signed}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_MAX_AGE}`,
            },
          });
        }
        return showLoginPage(true);
      }
      return showLoginPage();
    }

    // --- 路径过滤 ---
    for (const blocked of BLOCKED_PATHS) {
      if (url.pathname.toLowerCase().startsWith(blocked)) {
        return new Response('Not found', { status: 404 });
      }
    }

    // --- 路由匹配 ---
    const route = matchRoute(url.pathname);
    if (!route) return new Response('Not found', { status: 404 });

    // --- 认证检查（仅对 requireAuth 的路由）---
    if (route.requireAuth) {
      if (!(await isAuthenticated(request, env))) {
        const hasBasicAuth = (request.headers.get('Authorization') || '').startsWith('Basic ');
        if (hasBasicAuth) {
          return new Response('Unauthorized', {
            status: 401,
            headers: { 'WWW-Authenticate': 'Basic realm="uglink-bridge"' },
          });
        }
        return showLoginPage();
      }
    }

    // --- 获取代理凭证（每个端口独立缓存）---
    const proxy = await getProxyForPort(route.port, env);
    if (!proxy) return errorResponse('Failed to get proxy');

    // --- 构造代理 URL ---
    let proxyPath = url.pathname + url.search;
    if (route.stripPath) {
      // 去掉路由前缀，用 rewriteTo 替换
      // /webdav/       → /dav/
      // /webdav/folder → /dav/folder
      const remaining = url.pathname.slice(route.path.length);
      proxyPath = route.rewriteTo + remaining + url.search;
    }
    const proxyUrl = proxy.origin + proxyPath;

    // --- 转发请求 ---
    const proxyHeaders = new Headers();
    for (const [key, value] of request.headers) {
      const k = key.toLowerCase();
      if (k === 'host' || k === 'cookie') continue;
      if (k.startsWith('cf-') || k.startsWith('x-forwarded-')) continue;
      proxyHeaders.set(key, value);
    }
    proxyHeaders.set('Host', new URL(proxy.origin).host);
    proxyHeaders.set('Cookie', proxy.cookie);

    const proxyResponse = await fetch(proxyUrl, {
      method: request.method,
      headers: proxyHeaders,
      body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
    });

    // --- 过滤响应头 ---
    const responseHeaders = new Headers(proxyResponse.headers);
    for (const h of ['set-cookie', 'x-powered-by', 'server', 'x-aspnet-version', 'x-aspnetmvc-version']) {
      responseHeaders.delete(h);
    }

    return new Response(proxyResponse.body, {
      status: proxyResponse.status,
      statusText: proxyResponse.statusText,
      headers: responseHeaders,
    });
  },
};
