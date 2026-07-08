import JSEncrypt from 'jsencrypt';

// ==================== 安全配置 ====================
const SESSION_COOKIE = 'uglink-session';
const SESSION_MAX_AGE = 7 * 24 * 60 * 60; // 7 天
const BLOCKED_PATHS = ['/ugreen/', '/api/ugreen/']; // 管理路径黑名单
const ALLOWED_METHODS = ['GET', 'POST', 'HEAD', 'OPTIONS'];
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

// 获取或生成 HMAC key
async function getHmacKey(env: any): Promise<CryptoKey> {
  let keyData = await env.UGLINK_CACHE.get(HMAC_KEY_NAME);
  if (!keyData) {
    const key = await crypto.subtle.generateKey(
      { name: 'HMAC', hash: 'SHA-256' },
      true,
      ['sign', 'verify']
    );
    const exported = await crypto.subtle.exportKey('raw', key);
    keyData = btoa(String.fromCharCode(...new Uint8Array(exported)));
    await env.UGLINK_CACHE.put(HMAC_KEY_NAME, keyData);
  }
  const raw = Uint8Array.from(atob(keyData), c => c.charCodeAt(0));
  return crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

// 签名 cookie
async function signCookie(value: string, env: any): Promise<string> {
  const key = await getHmacKey(env);
  const data = new TextEncoder().encode(value);
  const sig = await crypto.subtle.sign('HMAC', key, data);
  const sigHex = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return `${value}.${sigHex}`;
}

// 验证 cookie
async function verifyCookie(signed: string, env: any): Promise<boolean> {
  const parts = signed.split('.');
  if (parts.length !== 2) return false;
  const value = parts[0];
  const key = await getHmacKey(env);
  const data = new TextEncoder().encode(value);
  const sig = Uint8Array.from(atob(parts[1]), c => c.charCodeAt(0));
  return crypto.subtle.verify('HMAC', key, sig, data);
}

// 检查认证
async function isAuthenticated(request: Request, env: any): Promise<boolean> {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(new RegExp(`${SESSION_COOKIE}=([^;]+)`));
  if (!match) return false;

  const signed = match[1];
  if (!(await verifyCookie(signed, env))) return false;

  // 检查过期（格式: timestamp）
  const value = signed.split('.')[0];
  const timestamp = parseInt(value, 10);
  if (isNaN(timestamp)) return false;
  if (Date.now() / 1000 - timestamp > SESSION_MAX_AGE) return false;

  return true;
}

// 返回登录页
function showLoginPage(error = false): Response {
  const html = error
    ? LOGIN_PAGE.replace('display: none', 'display: block')
    : LOGIN_PAGE;
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

// 通用错误响应（不泄露服务端详情）
function errorResponse(msg: string): Response {
  console.error('UGLINK Worker:', msg);
  return new Response('Service temporarily unavailable', { status: 500 });
}

// ==================== 主逻辑 ====================
export default {
  async fetch(request: Request, env: any, ctx: any): Promise<Response> {
    const url = new URL(request.url);

    // --- 1. HTTP 方法限制 ---
    if (!ALLOWED_METHODS.includes(request.method)) {
      return new Response('Method not allowed', { status: 405 });
    }

    // --- 2. 登录处理（在路径过滤之前）---
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

    // --- 3. 路径过滤 ---
    const pathname = url.pathname.toLowerCase();
    for (const blocked of BLOCKED_PATHS) {
      if (pathname.startsWith(blocked)) {
        return new Response('Not found', { status: 404 });
      }
    }

    // --- 4. 认证检查 ---
    if (!(await isAuthenticated(request, env))) {
      return showLoginPage();
    }

    // --- 5. 业务逻辑（原有反代 + 安全加固）---
    const baseUrl = env.BASE_URL;
    const port = env.PORT;
    const username = env.USERNAME;
    const rawPassword = env.PASSWORD;
    const cookieCacheKey = 'proxy_cookie';
    const originCacheKey = 'proxy_origin';

    let proxyCookie = await env.UGLINK_CACHE.get(cookieCacheKey);
    let proxyOrigin = await env.UGLINK_CACHE.get(originCacheKey);

    if (!proxyCookie) {
      // 获取加密公钥
      const checkUrl = `${baseUrl}/ugreen/v1/verify/check?token=`;
      const checkResponse = await fetch(checkUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username }),
      });

      if (!checkResponse.ok) {
        return errorResponse('Failed to get encryption key');
      }

      const rsaToken = checkResponse.headers.get('x-rsa-token');
      if (!rsaToken) {
        return errorResponse('No x-rsa-token in check response');
      }

      const encryptionPublicKey = atob(rsaToken);
      const encryptPassword = new JSEncrypt();
      encryptPassword.setPublicKey(encryptionPublicKey);
      const encryptedPassword = encryptPassword.encrypt(rawPassword);

      if (!encryptedPassword) {
        return errorResponse('Failed to encrypt password');
      }

      // 登录
      const loginUrl = `${baseUrl}/ugreen/v1/verify/login`;
      const loginResponse = await fetch(loginUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username,
          password: encryptedPassword,
          keepalive: true,
          otp: true,
          is_simple: true,
        }),
      });

      if (!loginResponse.ok) {
        return errorResponse('Login failed');
      }

      const loginJson = await loginResponse.json();

      if (loginJson.code !== 200) {
        return errorResponse('Login API error');
      }

      // 加密 token
      const encodedPublicKey = loginJson.data.public_key;
      const decodedPublicKey = atob(encodedPublicKey);
      const encrypt = new JSEncrypt();
      encrypt.setPublicKey(decodedPublicKey);
      const encryptedToken = encrypt.encrypt(loginJson.data.token);

      if (!encryptedToken) {
        return errorResponse('Failed to encrypt token');
      }

      // 获取 docker token
      const apiUrl = `${baseUrl}/ugreen/v1/gateway/proxy/dockerToken?port=${port}`;
      const response = await fetch(apiUrl, {
        headers: {
          'X-Ugreen-Token': encryptedToken,
          'X-Ugreen-Security-Key': loginJson.data.token_id,
        },
      });

      if (!response.ok) {
        return errorResponse('Failed to fetch docker token');
      }

      const data = await response.json();

      if (data.code === 200) {
        const redirectUrl = data.data.redirect_url;

        // SSRF 防护：验证 redirectUrl 来源
        const redirectOrigin = new URL(redirectUrl).origin;
        const allowedHostPattern = /\.ug(link|docker)\./;
        if (!allowedHostPattern.test(new URL(redirectUrl).hostname)) {
          return errorResponse('Invalid redirect target');
        }

        const redirectResponse = await fetch(redirectUrl);
        const responseBody = await redirectResponse.text();

        const tokenMatch = responseBody.match(/ugreen-proxy-token=([^;]+)/);
        if (tokenMatch) {
          proxyCookie = `ugreen-proxy-token=${tokenMatch[1]}`;
          proxyOrigin = redirectOrigin;
          await env.UGLINK_CACHE.put(cookieCacheKey, proxyCookie, { expirationTtl: 3600 });
          await env.UGLINK_CACHE.put(originCacheKey, proxyOrigin, { expirationTtl: 3600 });
        } else {
          return errorResponse('Auth token not found');
        }
      } else {
        return errorResponse('Docker token API error');
      }
    }

    // --- 6. 反向代理（带安全过滤）---
    const proxyUrl = proxyOrigin + url.pathname + url.search;

    const proxyHeaders = new Headers();
    for (const [key, value] of request.headers) {
      const k = key.toLowerCase();
      if (k === 'host' || k === 'cookie') continue;
      if (k.startsWith('cf-') || k.startsWith('x-forwarded-')) continue;
      proxyHeaders.set(key, value);
    }
    proxyHeaders.set('Host', new URL(proxyOrigin).host);
    proxyHeaders.set('Cookie', proxyCookie);

    const proxyResponse = await fetch(proxyUrl, {
      method: request.method,
      headers: proxyHeaders,
      body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
    });

    // 过滤响应头
    const responseHeaders = new Headers(proxyResponse.headers);
    const headersToRemove = ['set-cookie', 'x-powered-by', 'server', 'x-aspnet-version', 'x-aspnetmvc-version'];
    for (const h of headersToRemove) {
      responseHeaders.delete(h);
    }

    return new Response(proxyResponse.body, {
      status: proxyResponse.status,
      statusText: proxyResponse.statusText,
      headers: responseHeaders,
    });
  },
};
