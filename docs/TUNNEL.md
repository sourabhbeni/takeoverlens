# Running TakeoverLens through a Cloudflare Tunnel

Expose the local TakeoverLens server to the internet (e.g. use it from your
phone anywhere) without opening ports or paying for hosting. Your machine runs
the app; Cloudflare just proxies traffic to it.

## Quick tunnel (2 minutes, temporary URL)

```bash
# 1. Start TakeoverLens
pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 8001

# 2. In another terminal, install cloudflared and expose it
brew install cloudflared        # macOS
# sudo apt install cloudflared  # Debian/Ubuntu (after adding Cloudflare's repo)

cloudflared tunnel --url http://127.0.0.1:8001
```

You get a public `https://<random>.trycloudflare.com` URL. Open it on your phone.
Done. The URL changes every restart — fine for personal use.

## Named tunnel (stable URL: `takeoverlens.beniwal.me`)

One-time setup (needs your Cloudflare account):

```bash
cloudflared tunnel login                 # opens browser, pick beniwal.me zone
cloudflared tunnel create takeoverlens
cloudflared tunnel route dns takeoverlens takeoverlens.beniwal.me
```

Create `~/.cloudflared/config.yml`:

```yaml
tunnel: takeoverlens
credentials-file: ~/.cloudflared/<tunnel-id>.json
ingress:
  - hostname: takeoverlens.beniwal.me
    service: http://127.0.0.1:8001
  - service: http_status:404
```

Then run both:

```bash
uvicorn app:app --host 127.0.0.1 --port 8001
cloudflared tunnel run takeoverlens
```

## Keep it alive

**macOS** (launchd) — save as `~/Library/LaunchAgents/com.takeoverlens.plist`
(pointing at a small shell script that starts uvicorn + cloudflared), then
`launchctl load ~/Library/LaunchAgents/com.takeoverlens.plist`.

**Linux** (systemd) — two simple units, one for uvicorn, one for
`cloudflared tunnel run takeoverlens`, both `WantedBy=multi-user.target`.

## Lock it down

A tunnel URL is **public**. The in-app authorization checkbox is a reminder, not
access control. For a named tunnel, put Cloudflare Access (Zero Trust, free for
50 users) in front of the hostname so only you can open it:

Cloudflare dashboard → Zero Trust → Access → Applications → Add
`takeoverlens.beniwal.me` → allow only your email (one-time PIN or Google login).

Do this before sharing the URL pattern with anyone.
