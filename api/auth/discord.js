const axios = require('axios');
const { kv } = require('@vercel/kv');

const allowedOrigins = [
  'https://aware-amount-178968.framer.app',
  'https://almeidaracingacademy.com',
  'https://www.almeidaracingacademy.com',
];

const allowedReturnUrls = [
  'https://aware-amount-178968.framer.app/sign-in',
  'https://aware-amount-178968.framer.app/account',
  'https://almeidaracingacademy.com/sign-in',
  'https://almeidaracingacademy.com/account',
  'https://www.almeidaracingacademy.com/sign-in',
  'https://www.almeidaracingacademy.com/account',
];
const DEFAULT_RETURN_URL = allowedReturnUrls[0];

const ACCOUNT_CONFLICT_MESSAGE = "This email is already registered. Please sign in using a known method, then link this provider from your account settings.";

const redirectHostAllowlist = new Set([
  ...allowedReturnUrls.map(getHost),
  'aware-amount-178968.framer.app',
  'almeidaracingacademy.com',
  'www.almeidaracingacademy.com',
].filter(Boolean));
  
function getHost(url) {
  try {
    return new URL(url).host;
  } catch (err) {
    return null;
  }
}

function sanitizeRedirect(targetUrl, fallbackUrl) {
  if (!targetUrl) return fallbackUrl;
  try {
    const parsed = new URL(targetUrl);
    if (parsed.protocol !== 'https:') {
      return fallbackUrl;
    }
    if (allowedReturnUrls.includes(parsed.toString())) {
      return parsed.toString();
    }
    if (redirectHostAllowlist.has(parsed.host)) {
      return parsed.toString();
    }
  } catch (err) {
    return fallbackUrl;
  }
  return fallbackUrl;
}

// Rate limiting: 10 requests per minute per IP
async function checkRateLimit(ip) {
  const key = `discord:ratelimit:${ip}`;
  const count = await kv.incr(key);
  if (count === 1) await kv.expire(key, 60);
  return count <= 10;
}

module.exports = async (req, res) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Rate limiting
  const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.connection?.remoteAddress || 'unknown';
  if (!await checkRateLimit(ip)) {
    return res.status(429).json({ error: 'Too many requests. Please try again later.' });
  }

  const { code } = req.query;

  if (!code) {
    return handleStart(req, res);
  }

  return handleCallback(req, res, code);
};

async function handleStart(req, res) {
  if (!process.env.DISCORD_CLIENT_ID) {
    return res.status(500).send('Discord client ID not configured');
  }

  const intent = (req.query.intent || 'login').toLowerCase();
  if (!['login', 'link'].includes(intent)) {
    return res.status(400).send('Invalid intent');
  }

  const requestedReturnUrl = req.query.return_url;
  const returnUrl = sanitizeRedirect(requestedReturnUrl, DEFAULT_RETURN_URL);

  let linkPersonUid = null;
  if (intent === 'link') {
    const linkToken = req.query.link_token;
    const requestedLinkUid = req.query.link_person_uid;

    if (!linkToken || !requestedLinkUid) {
      return res.status(400).send('Missing linking parameters');
    }

    try {
      const profile = await verifyOutsetaAccessToken(linkToken);
      if (profile?.Uid !== requestedLinkUid) {
        return res.status(403).send('Invalid linking session');
      }
    } catch (err) {
      console.error('Outseta token verification failed', err.message);
      return res.status(403).send('Invalid linking session');
    }

    linkPersonUid = requestedLinkUid;
  }

  const redirectUri = `${getBaseUrl(req)}/api/auth/discord`;

  // Store return URL in Vercel KV with 10 minute expiration
  const state = require('crypto').randomBytes(16).toString('hex');
  await kv.set(
    `discord:state:${state}`,
    { returnUrl, intent, linkPersonUid, createdAt: Date.now() },
    { ex: 600 }
  );

  const url =
    'https://discord.com/api/oauth2/authorize' +
    `?client_id=${encodeURIComponent(process.env.DISCORD_CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&response_type=code` +
    `&scope=identify%20email` +
    `&state=${encodeURIComponent(state)}` +
    `&prompt=none`;

  res.writeHead(302, { Location: url });
  res.end();
}

async function handleCallback(req, res, code) {
  if (req.query.error) {
    console.error('Discord OAuth error:', req.query.error);
    return res.send(renderErrorPage('Discord authentication failed.'));
  }

  try {
    const state = req.query.state;
    const stateData = await kv.get(`discord:state:${state}`);
    const returnUrl = stateData?.returnUrl;
    const intent = stateData?.intent || 'login';
    const linkPersonUid = stateData?.linkPersonUid || null;

    if (!returnUrl) {
      console.error('State not found for Discord OAuth');
      return res.send(renderErrorPage('Session expired. Please try again.'));
    }

    await kv.del(`discord:state:${state}`);

    const redirectUri = `${getBaseUrl(req)}/api/auth/discord`;

    const tokenResponse = await axios.post(
      'https://discord.com/api/oauth2/token',
      new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: process.env.DISCORD_CLIENT_ID,
        client_secret: process.env.DISCORD_CLIENT_SECRET,
        redirect_uri: redirectUri,
      }),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: 8000,
      }
    );

    const discordAccessToken = tokenResponse.data.access_token;

    const userResponse = await axios.get('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${discordAccessToken}` },
      timeout: 8000,
    });

    const discordUser = userResponse.data;
    const discordId = discordUser.id;
    const email = (discordUser.email || `${discordId}@discord.user`).toLowerCase();

    const existingByDiscordId = await findPersonByField('DiscordId', discordId);

    if (existingByDiscordId) {
      if (intent === 'link') {
        if (!linkPersonUid || existingByDiscordId.Uid !== linkPersonUid) {
          return res.send(renderRedirectWithError(returnUrl, 'account_exists', ACCOUNT_CONFLICT_MESSAGE, 'discord'));
        }

        return res.send(renderLinkSuccessPage(returnUrl, 'discord'));
      }

      const outsetaToken = await generateOutsetaToken(existingByDiscordId.Email);
      return res.send(renderSuccessPage(outsetaToken, returnUrl));
    }

    if (intent === 'link') {
      if (!linkPersonUid) {
        return res.send(renderErrorPage('Linking session expired.'));
      }

      const person = await getPersonByUid(linkPersonUid);
      if (!person) {
        return res.send(renderErrorPage('Unable to locate your account.'));
      }

      await updatePerson(linkPersonUid, buildDiscordUpdatePayload(person, discordUser));

      return res.send(renderLinkSuccessPage(returnUrl, 'discord'));
    }

    const existingByEmail = await findPersonByEmail(email);
    if (existingByEmail) {
      return res.send(renderRedirectWithError(returnUrl, 'account_exists', ACCOUNT_CONFLICT_MESSAGE, 'discord'));
    }

    const createdPerson = await createDiscordOutsetaUser(discordUser);
    const outsetaToken = await generateOutsetaToken(createdPerson.Email);

    return res.send(renderSuccessPage(outsetaToken, returnUrl));
  } catch (err) {
    dumpError('[DiscordSSO]', err);
    return res.send(renderErrorPage('Unable to complete Discord sign in.'));
  }
}

async function generateOutsetaToken(email) {
  const apiBase = `https://${process.env.OUTSETA_DOMAIN}/api/v1`;
  const authHeader = { Authorization: `Outseta ${process.env.OUTSETA_API_KEY}:${process.env.OUTSETA_SECRET_KEY}` };

  const tokenResponse = await axios.post(
    `${apiBase}/tokens`,
    { username: email },
    {
      headers: { ...authHeader, 'Content-Type': 'application/json' },
      timeout: 8000,
    }
  );

  return tokenResponse.data.access_token || tokenResponse.data;
}

function renderSuccessPage(token, returnUrl) {
  return `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Signing in...</title>
  </head>
  <body>
    <script>
      (function() {
        const token = ${JSON.stringify(token)};
        const returnUrl = ${JSON.stringify(returnUrl)};
        
        const url = new URL(returnUrl);
        url.hash = 'discord_token=' + token;
        window.location.href = url.toString();
      })();
    </script>
  </body>
</html>`;
}

function renderErrorPage(message) {
  return `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Discord Sign In</title>
    <style>
      body { margin: 0; font-family: sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; }
      p { color: #555; }
    </style>
  </head>
  <body>
    <div style="text-align:center;">
      <h1>Sign in failed</h1>
      <p>${message}</p>
    </div>
  </body>
</html>`;
}

function renderRedirectWithError(returnUrl, code, message, provider) {
  const url = new URL(returnUrl);
  const params = new URLSearchParams(url.hash?.replace(/^#/, '') || '');
  params.set('error', code);
  if (message) {
    params.set('message', message);
  }
  if (provider) {
    params.set('provider', provider);
  }
  url.hash = params.toString();

  return `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Redirecting...</title>
  </head>
  <body>
    <script>
      window.location.href = ${JSON.stringify(url.toString())};
    </script>
  </body>
</html>`;
}

function renderLinkSuccessPage(returnUrl, provider) {
  const url = new URL(returnUrl);
  const params = new URLSearchParams(url.hash?.replace(/^#/, '') || '');
  params.set('link', 'success');
  params.set('provider', provider);
  url.hash = params.toString();

  return `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Link Successful</title>
  </head>
  <body>
    <script>
      window.location.href = ${JSON.stringify(url.toString())};
    </script>
  </body>
</html>`;
}

function getBaseUrl(req) {
  const protocol = req.headers['x-forwarded-proto'] || 'https';
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  return `${protocol}://${host}`;
}

function getOutsetaApiBase() {
  if (!process.env.OUTSETA_DOMAIN) {
    throw new Error('OUTSETA_DOMAIN not configured');
  }
  return `https://${process.env.OUTSETA_DOMAIN}/api/v1`;
}

function getOutsetaAuthHeaders() {
  if (!process.env.OUTSETA_API_KEY || !process.env.OUTSETA_SECRET_KEY) {
    throw new Error('Outseta API credentials not configured');
  }

  return {
    Authorization: `Outseta ${process.env.OUTSETA_API_KEY}:${process.env.OUTSETA_SECRET_KEY}`,
    'Content-Type': 'application/json',
  };
}

async function verifyOutsetaAccessToken(token) {
  if (!token) {
    throw new Error('Missing Outseta access token');
  }

  const apiBase = getOutsetaApiBase();

  const response = await axios.get(`${apiBase}/profile`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
    timeout: 8000,
  });

  return response.data;
}

async function getPersonByUid(uid) {
  if (!uid) return null;

  const apiBase = getOutsetaApiBase();
  const response = await axios.get(`${apiBase}/crm/people/${uid}`, {
    headers: getOutsetaAuthHeaders(),
    timeout: 8000,
  });

  return response.data;
}

async function findPersonByEmail(email) {
  if (!email) return null;

  const apiBase = getOutsetaApiBase();
  const response = await axios.get(`${apiBase}/crm/people`, {
    headers: getOutsetaAuthHeaders(),
    params: { Email: email },
    timeout: 8000,
  });

  return response.data.items?.[0] ?? null;
}

async function findPersonByField(field, value) {
  if (!field || value == null) return null;

  const apiBase = getOutsetaApiBase();
  const response = await axios.get(`${apiBase}/crm/people`, {
    headers: getOutsetaAuthHeaders(),
    params: { [field]: value },
    timeout: 8000,
  });

  return response.data.items?.[0] ?? null;
}

async function updatePerson(uid, payload) {
  if (!uid) throw new Error('Cannot update person without UID');

  const apiBase = getOutsetaApiBase();
  await axios.put(`${apiBase}/crm/people/${uid}`, payload, {
    headers: getOutsetaAuthHeaders(),
    timeout: 8000,
  });
}

async function createRegistration(payload) {
  const apiBase = getOutsetaApiBase();
  const response = await axios.post(`${apiBase}/crm/registrations`, payload, {
    headers: getOutsetaAuthHeaders(),
    timeout: 8000,
  });

  return response.data;
}

function dumpError(tag, error) {
  const payload = {
    tag,
    message: error?.message,
    stack: error?.stack,
    response: error?.response
      ? {
          status: error.response.status,
          statusText: error.response.statusText,
          data: toJsonSafe(error.response.data),
          headers: error.response.headers,
        }
      : null,
    request: error?.config
      ? {
          method: error.config.method,
          url: error.config.url,
          data: toJsonSafe(error.config.data),
          headers: error.config.headers,
        }
      : null,
  };

  try {
    console.error(`${tag} error`, JSON.stringify(payload, null, 2));
  } catch (serializationError) {
    console.error(`${tag} error (serialization failed)`, payload);
  }
}

function toJsonSafe(value) {
  if (value == null) return null;
  if (typeof value === 'string') return value;
  try {
    return JSON.parse(JSON.stringify(value));
  } catch (err) {
    return String(value);
  }
}

function buildDiscordUpdatePayload(person, discordUser) {
  const email = person.Email;
  const displayName = discordUser.global_name || discordUser.username || person.FirstName || 'Discord User';
  const nameParts = displayName.split(' ');
  const firstName = person.FirstName || nameParts.shift() || 'Discord';
  const lastName = person.LastName || nameParts.join(' ') || 'User';

  return {
    Uid: person.Uid,
    Email: email,
    FirstName: firstName,
    LastName: lastName,
    DiscordUsername: discordUser.username || displayName || '',
    DiscordId: discordUser.id,
  };
}

async function createDiscordOutsetaUser(discordUser) {
  const email = (discordUser.email || `${discordUser.id}@discord.user`).toLowerCase();
  const displayName = discordUser.global_name || discordUser.username || 'Discord User';
  const nameParts = displayName.split(' ');
  const firstName = nameParts.shift() || 'Discord';
  const lastName = nameParts.join(' ') || 'User';

  const registration = await createRegistration({
    Name: `${firstName} ${lastName}`,
    PersonAccount: [
      {
        IsPrimary: true,
        Person: {
          Email: email,
          FirstName: firstName,
          LastName: lastName,
          DiscordUsername: discordUser.username || displayName || '',
          DiscordId: discordUser.id,
        },
      },
    ],
    Subscriptions: [
      {
        Plan: {
          Uid: process.env.OUTSETA_FREE_PLAN_UID,
        },
        BillingRenewalTerm: 1,
      },
    ],
  });

  return registration.PrimaryContact;
}