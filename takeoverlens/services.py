"""Known takeoverable services: CNAME suffixes + unclaimed fingerprints.

Curated subset of the public can-i-take-over-xyz dataset. A subdomain is only
flagged VULNERABLE when its HTTP response matches one of these fingerprints —
a 404 or error page alone is never enough.
"""

SERVICES = [
    {"name": "GitHub Pages", "suffixes": [".github.io"],
     "fingerprints": ["There isn't a GitHub Pages site here."]},
    {"name": "Heroku", "suffixes": [".herokuapp.com", ".herokudns.com"],
     "fingerprints": ["No such app", "There's nothing here, yet."]},
    {"name": "AWS S3", "suffixes": [".s3.amazonaws.com", ".s3-website.", ".s3."],
     "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"]},
    {"name": "Azure Web Apps", "suffixes": [".azurewebsites.net"],
     "fingerprints": ["404 Web Site not found."]},
    {"name": "Azure Cloud", "suffixes": [".cloudapp.net", ".trafficmanager.net", ".blob.core.windows.net"],
     "fingerprints": ["404 Web Site not found."]},
    {"name": "Netlify", "suffixes": [".netlify.app", ".netlify.com"],
     "fingerprints": ["Not Found - Request ID:"]},
    {"name": "Vercel", "suffixes": [".vercel.app", ".now.sh"],
     "fingerprints": ["The deployment could not be found on Vercel."]},
    {"name": "GitLab Pages", "suffixes": [".gitlab.io"],
     "fingerprints": ["The page you are looking for is not found"]},
    {"name": "Bitbucket", "suffixes": [".bitbucket.io"],
     "fingerprints": ["Repository not found"]},
    {"name": "Shopify", "suffixes": [".myshopify.com"],
     "fingerprints": ["Sorry, this shop is currently unavailable."]},
    {"name": "Tumblr", "suffixes": [".tumblr.com"],
     "fingerprints": ["Whatever you were looking for doesn't currently exist"]},
    {"name": "WordPress.com", "suffixes": [".wordpress.com"],
     "fingerprints": ["Do you want to register"]},
    {"name": "Ghost", "suffixes": [".ghost.io"],
     "fingerprints": ["The thing you were looking for is no longer here"]},
    {"name": "Help Scout", "suffixes": [".helpscoutdocs.com"],
     "fingerprints": ["No settings were found for this company"]},
    {"name": "Surge.sh", "suffixes": [".surge.sh"],
     "fingerprints": ["project not found"]},
    {"name": "Pantheon", "suffixes": [".pantheonsite.io"],
     "fingerprints": ["404 error unknown site!"]},
    {"name": "Strikingly", "suffixes": [".s.strikinglydns.com"],
     "fingerprints": ["But if you're looking to build your own website"]},
    {"name": "UserVoice", "suffixes": [".uservoice.com"],
     "fingerprints": ["This UserVoice subdomain is currently available!"]},
    {"name": "Zendesk", "suffixes": [".zendesk.com"],
     "fingerprints": ["Help Center Closed"]},
    {"name": "Fastly", "suffixes": [".fastly.net"],
     "fingerprints": ["Fastly error: unknown domain"]},
    {"name": "Cargo", "suffixes": [".cargocollections.com"],
     "fingerprints": ["If you're looking for something specific"]},
    {"name": "FeedPress", "suffixes": [".feedpress.me"],
     "fingerprints": ["The feed has not been found."]},
    {"name": "Unbounce", "suffixes": [".unbouncepages.com"],
     "fingerprints": ["The requested URL was not found on this server"]},
    {"name": "Teamwork", "suffixes": [".teamwork.com"],
     "fingerprints": ["Oops - We didn't find your site."]},
]


def match_service(cname_target: str):
    """Return the service dict whose suffix matches the CNAME target, else None."""
    target = cname_target.lower().rstrip(".")
    for svc in SERVICES:
        for suffix in svc["suffixes"]:
            if target == suffix.lstrip(".") or target.endswith(suffix):
                return svc
    return None
