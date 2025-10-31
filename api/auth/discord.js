/**
 * 🎮 DISCORD SSO FOR VERCEL
 * 
 * File structure:
 * /api
 *   /auth
 *     /discord.js  ← This file
 * 
 * Endpoint: https://your-project.vercel.app/api/auth/discord
 * 
 * Environment Variables (in Vercel Dashboard):
 * - DISCORD_CLIENT_ID
 * - DISCORD_CLIENT_SECRET
 * - OUTSETA_DOMAIN
 * - OUTSETA_API_KEY
 * - OUTSETA_SECRET_KEY
 */

const axios = require('axios');

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Main Handler (Vercel Serverless Function)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

module.exports = async (req, res) => {
  // Enable CORS for your Framer site
  const allowedOrigins = [
    'https://aware-amount-178968.framer.app',
    'https://almeidaracingacademy.com',
  ];
  
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin) || origin?.endsWith('.framer.app')) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const { action } = req.query;

  try {
    switch (action) {
      case 'start':
        return handleStart(req, res);
      case 'callback':
        return handleCallback(req, res);
      default:
        return res.status(404).json({ error: 'Unknown action' });
    }
  } catch (error) {
    console.error('Discord SSO error:', error);
    return res.status(500).json({
      error: 'Authentication failed',
      message: error.message,
    });
  }
};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Action: Start OAuth Flow
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

function handleStart(req, res) {
  const redirectUri = `${getBaseUrl(req)}/api/auth/discord?action=callback`;
  
  const discordAuthUrl = new URL('https://discord.com/api/oauth2/authorize');
  discordAuthUrl.searchParams.append('client_id', process.env.DISCORD_CLIENT_ID);
  discordAuthUrl.searchParams.append('redirect_uri', redirectUri);
  discordAuthUrl.searchParams.append('response_type', 'code');
  discordAuthUrl.searchParams.append('scope', 'identify email');

  res.redirect(307, discordAuthUrl.toString());
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Action: Handle OAuth Callback
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function handleCallback(req, res) {
  const { code, error, error_description } = req.query;

  // Handle OAuth errors from Discord
  if (error) {
    console.error('Discord OAuth error:', error, error_description);
    
    // Sanitize error messages to prevent XSS
    const safeError = String(error).replace(/[<>"']/g, '');
    const safeDescription = String(error_description || 'Authentication failed').replace(/[<>"']/g, '');
    
    return res.send(`
      <!DOCTYPE html>
      <html>
        <head><title>Authentication Failed</title></head>
        <body>
          <script>
            if (window.opener) {
              // Only send to allowed origins
              const allowedOrigins = [
                'https://aware-amount-178968.framer.app',
                'https://almeidaracingacademy.com'
              ];
              
              // Check if opener is from allowed origin
              const targetOrigin = window.opener.location.origin;
              if (allowedOrigins.includes(targetOrigin) || targetOrigin.endsWith('.framer.app')) {
                window.opener.postMessage({
                  type: 'DISCORD_AUTH_ERROR',
                  error: ${JSON.stringify(safeError)},
                  description: ${JSON.stringify(safeDescription)}
                }, targetOrigin);
              }
              window.close();
            }
          </script>
          <p>Authentication failed. You can close this window.</p>
        </body>
      </html>
    `);
  }

  if (!code) {
    return res.status(400).send('Missing authorization code');
  }

  const redirectUri = `${getBaseUrl(req)}/api/auth/discord?action=callback`;

  // 1. Exchange code for Discord access token
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
      headers: { 
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    }
  );

  const { access_token: discordAccessToken } = tokenResponse.data;

  // 2. Get Discord user info
  const userInfoResponse = await axios.get(
    'https://discord.com/api/users/@me',
    {
      headers: { Authorization: `Bearer ${discordAccessToken}` },
    }
  );

  const discordUser = userInfoResponse.data;
  console.log('✓ Discord user authenticated:', discordUser.email || discordUser.username);

  // 3. Find or create Outseta user
  const outsetaUser = await findOrCreateOutsetaUser(discordUser);

  // 4. Generate Outseta JWT access token
  const outsetaAccessToken = await generateOutsetaToken(outsetaUser);
  
  if (!outsetaAccessToken) {
    throw new Error('Failed to generate Outseta token');
  }

  // 5. Close popup and send token to opener window
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <title>Authentication Successful</title>
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #5865F2 0%, #7289DA 100%);
            color: white;
          }
          .container {
            text-align: center;
            padding: 2rem;
          }
          .checkmark {
            font-size: 4rem;
            animation: scaleIn 0.5s ease-out;
          }
          @keyframes scaleIn {
            from { transform: scale(0); }
            to { transform: scale(1); }
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="checkmark">✓</div>
          <h1>Authentication Successful!</h1>
          <p>This window will close automatically...</p>
        </div>
        <script>
          (function() {
            try {
              // Send token to parent window with origin validation
              if (window.opener) {
                const allowedOrigins = [
                  'https://aware-amount-178968.framer.app',
                  'https://almeidaracingacademy.com'
                ];
                
                // Get opener origin and validate
                const targetOrigin = window.opener.location.origin;
                if (allowedOrigins.includes(targetOrigin) || targetOrigin.endsWith('.framer.app')) {
                  window.opener.postMessage({
                    type: 'DISCORD_AUTH_SUCCESS',
                    outsetaToken: ${JSON.stringify(outsetaAccessToken)}
                  }, targetOrigin);
                  
                  // Close after a short delay
                  setTimeout(() => window.close(), 1500);
                } else {
                  console.error('Unauthorized origin:', targetOrigin);
                }
              }
            } catch (error) {
              console.error('Failed to communicate with parent window:', error);
            }
          })();
        </script>
      </body>
    </html>
  `);
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Helper: Find or Create Outseta User
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function findOrCreateOutsetaUser(discordUser) {
  const outsetaApiUrl = `https://${process.env.OUTSETA_DOMAIN}/api/v1`;
  const auth = `${process.env.OUTSETA_API_KEY}:${process.env.OUTSETA_SECRET_KEY}`;

  // Use email if available, otherwise use Discord ID + username
  const userEmail = discordUser.email || `${discordUser.id}@discord.user`;
  const userName = discordUser.global_name || discordUser.username;

  // Try to find existing user
  try {
    const searchResponse = await axios.get(
      `${outsetaApiUrl}/crm/people`,
      {
        headers: { Authorization: `Outseta ${auth}` },
        params: { Email: userEmail },
      }
    );

    if (searchResponse.data.items && searchResponse.data.items.length > 0) {
      console.log('✓ Found existing Outseta user:', userEmail);
      return searchResponse.data.items[0];
    }
  } catch (error) {
    console.log('User not found, will create new user');
  }

  // Create new user
  console.log('✓ Creating new Outseta user:', userEmail);
  const createResponse = await axios.post(
    `${outsetaApiUrl}/crm/people`,
    {
      Email: userEmail,
      FirstName: userName || 'Discord',
      LastName: 'User',
      Account: {
        Name: userName || userEmail,
        // Optional: Assign to a default plan (e.g., Free tier)
        // PlanUid: 'YOUR_FREE_PLAN_UID',
      },
    },
    {
      headers: {
        Authorization: `Outseta ${auth}`,
        'Content-Type': 'application/json',
      },
    }
  );

  return createResponse.data;
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Helper: Generate Outseta JWT Token
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function generateOutsetaToken(outsetaUser) {
  const outsetaApiUrl = `https://${process.env.OUTSETA_DOMAIN}/api/v1`;
  const auth = `${process.env.OUTSETA_API_KEY}:${process.env.OUTSETA_SECRET_KEY}`;

  // Generate JWT token using server-side authentication
  const tokenResponse = await axios.post(
    `${outsetaApiUrl}/tokens`,
    {},  // Empty body for server-side auth
    {
      headers: {
        Authorization: `Outseta ${auth}`,
        'Content-Type': 'application/json',
      },
      params: {
        email: outsetaUser.Email,
      }
    }
  );

  const token = tokenResponse.data.access_token || tokenResponse.data;
  console.log('✓ Generated Outseta token for:', outsetaUser.Email);
  
  if (!token) {
    throw new Error('Outseta token generation returned empty response');
  }
  
  return token;
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Helper: Get Base URL
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

function getBaseUrl(req) {
  const protocol = req.headers['x-forwarded-proto'] || 'https';
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  return `${protocol}://${host}`;
}

