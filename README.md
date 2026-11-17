# Phishing web detector

Black-and-white web page plus a small Node backend that checks pasted links against live blocklists.

## Run it

Requires Node 18 or newer. No `npm install` needed.

    node server.js
    # then open http://localhost:3000

Optional environment variables:

| Variable | Purpose |
|---|---|
| `PORT` | Port to listen on (default 3000) |
| `PT_USER` | Your name or app name, sent to PhishTank as `User-Agent: phishtank/<name>` |
| `PHISHTANK_KEY` | PhishTank application key. Without one, downloads are limited to a few per day |
| `GSB_KEY` | Google Safe Browsing API key. Adds a live per-link lookup |

Example:

    PT_USER=myname GSB_KEY=xxxx node server.js

## What it checks

- **PhishTank**: downloads the `online-valid` list at start and every 6 hours.
- **OpenPhish**: downloads the free community feed at start and every hour (no key needed).
- **Google Safe Browsing** (optional): queried live for each link.
- The page's own link analysis (IP hosts, look-alike characters, brand impersonation and so on) is combined with these.

An exact match on a blocklist is shown as "Known phishing site". A match on the same host but a different page is a strong warning, not proof, because shared hosts can carry both good and bad pages.

Feeds are cached in `data/`, so a restart still works if a download fails.

## API

- `GET /api/check?url=<link>` returns `{ listed, hostListed, matches[], sources{} }`
- `GET /api/status` returns the feed counts and last update times

The API is rate limited to 40 requests per minute per IP. If you put this on the public internet, run it behind HTTPS and a reverse proxy.
