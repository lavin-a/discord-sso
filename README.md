# Discord SSO Backend

Backend API for Discord Single Sign-On integration with Outseta.

## Deployment

Deploy to Vercel with the following environment variables:

- `DISCORD_CLIENT_ID` - Your Discord OAuth client ID
- `DISCORD_CLIENT_SECRET` - Your Discord OAuth client secret
- `OUTSETA_DOMAIN` - Your Outseta domain (e.g., yourcompany.outseta.com)
- `OUTSETA_API_KEY` - Your Outseta API key
- `OUTSETA_SECRET_KEY` - Your Outseta secret key

## Getting Discord OAuth Credentials

1. Go to https://discord.com/developers/applications
2. Create a new application
3. Go to OAuth2 settings
4. Copy Client ID and Client Secret
5. Add redirect URL: `https://your-project.vercel.app/api/auth/discord?action=callback`

## Endpoints

- `GET /api/auth/discord?action=start` - Start OAuth flow
- `GET /api/auth/discord?action=callback` - OAuth callback

## Usage

After deployment, use this URL in your Framer DiscordSSOButton component:
```
https://your-project.vercel.app/api/auth/discord
```

## Deploy Command

```bash
vercel --prod
```

