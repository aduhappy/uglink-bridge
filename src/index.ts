import JSEncrypt from 'jsencrypt';

export default {
  async fetch(request, env, ctx) {
    const baseUrl = env.BASE_URL;
    const port = env.PORT;
    const username = env.USERNAME;
    const rawPassword = env.PASSWORD;
    const cookieCacheKey = 'proxy_cookie';
    const originCacheKey = 'proxy_origin';

    // Check cache
    let proxyCookie = await env.UGLINK_CACHE.get(cookieCacheKey);
    let proxyOrigin = await env.UGLINK_CACHE.get(originCacheKey);

    if (!proxyCookie) {
      // First get the encryption public key
      const checkUrl = `${baseUrl}/ugreen/v1/verify/check?token=`;
      const checkResponse = await fetch(checkUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          username: username
        })
      });

      if (!checkResponse.ok) {
        console.error('UGLINK Worker: Failed to get encryption key');
        return new Response('Failed to get encryption key', { status: 500 });
      }

      const rsaToken = checkResponse.headers.get('x-rsa-token');

      if (!rsaToken) {
        console.error('UGLINK Worker: No x-rsa-token in check response');
        return new Response('No x-rsa-token in check response', { status: 500 });
      }

      const encryptionPublicKey = atob(rsaToken);
      // Encrypt password with the fetched public key
      const encryptPassword = new JSEncrypt();
      encryptPassword.setPublicKey(encryptionPublicKey);
      const encryptedPassword = encryptPassword.encrypt(rawPassword);

      if (!encryptedPassword) {
        console.error('UGLINK Worker: Failed to encrypt password');
        return new Response('Failed to encrypt password', { status: 500 });
      }

      // Login to get session
      const loginUrl = `${baseUrl}/ugreen/v1/verify/login`;
      const loginResponse = await fetch(loginUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          username: username,
          password: encryptedPassword,
          keepalive: true,
          otp: true,
          is_simple: true
        })
      });

      if (!loginResponse.ok) {
        console.error('UGLINK Worker: Login failed', { status: loginResponse.status });
        return new Response('Failed to login', { status: 500 });
      }

      const loginJson = await loginResponse.json();

      if (loginJson.code !== 200) {
        console.error('UGLINK Worker: Login API error', { msg: loginJson.msg });
        return new Response('Login API error: ' + loginJson.msg, { status: 500 });
      }

      // Decode public key
      const encodedPublicKey = loginJson.data.public_key;
      const decodedPublicKey = atob(encodedPublicKey);

      // Encrypt token with RSA
      const encrypt = new JSEncrypt();
      encrypt.setPublicKey(decodedPublicKey);
      const encryptedToken = encrypt.encrypt(loginJson.data.token);

      if (!encryptedToken) {
        console.error('UGLINK Worker: Failed to encrypt token');
        return new Response('Failed to encrypt token', { status: 500 });
      }

      const loginData = {
        ugreenToken: encryptedToken,
        securityKey: loginJson.data.token_id
      };
      // Now fetch docker token with headers
      const apiUrl = `${baseUrl}/ugreen/v1/gateway/proxy/dockerToken?port=${port}`;
      const response = await fetch(apiUrl, {
        headers: {
          'X-Ugreen-Token': loginData.ugreenToken,
          'X-Ugreen-Security-Key': loginData.securityKey
        }
      });

      if (!response.ok) {
        console.error('UGLINK Worker: Failed to fetch docker token', { status: response.status });
        return new Response('Failed to fetch docker token', { status: 500 });
      }

      const data = await response.json();

      if (data.code === 200) {
        const redirectUrl = data.data.redirect_url;

        const redirectResponse = await fetch(redirectUrl);
        const responseBody = await redirectResponse.text();

        // Extract ugreen-proxy-token from JavaScript document.cookie in HTML body
        const tokenMatch = responseBody.match(/ugreen-proxy-token=([^;]+)/);
        if (tokenMatch) {
          proxyCookie = `ugreen-proxy-token=${tokenMatch[1]}`;
          proxyOrigin = new URL(redirectUrl).origin;
          // Cache proxy cookie and origin for 1 hour
          await env.UGLINK_CACHE.put(cookieCacheKey, proxyCookie, { expirationTtl: 3600 });
          await env.UGLINK_CACHE.put(originCacheKey, proxyOrigin, { expirationTtl: 3600 });
        } else {
          console.error('UGLINK Worker: No ugreen-proxy-token found in response body');
          return new Response('No ugreen-proxy-token found in response body', { status: 500 });
        }
      } else {
        console.error('UGLINK Worker: API returned error', { msg: data.msg });
        return new Response('API returned error: ' + data.msg, { status: 500 });
      }
    }

    // Reverse proxy to the cached origin with the cookie
    const url = new URL(request.url);
    const proxyUrl = proxyOrigin + url.pathname + url.search;

    // Filter and set headers for proxy
    const proxyHeaders = new Headers();
    for (const [key, value] of request.headers) {
      if (key.toLowerCase() === 'host') continue; // Don't forward host
      if (key.toLowerCase().startsWith('cf-')) continue; // Don't forward Cloudflare headers
      if (key.toLowerCase().startsWith('x-forwarded-')) continue; // Don't forward forwarded headers
      proxyHeaders.set(key, value);
    }
    proxyHeaders.set('Host', new URL(proxyOrigin).host);
    proxyHeaders.set('Cookie', proxyCookie);

    const proxyResponse = await fetch(proxyUrl, {
      method: request.method,
      headers: proxyHeaders,
      body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined
    });

    return proxyResponse;
  }
};
