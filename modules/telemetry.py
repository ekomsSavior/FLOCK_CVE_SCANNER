#!/usr/bin/env python3
"""
telemetry.py — Analytics / third-party service detection for FLOCK_scan

Scrapes the admin web UI body for:
  - Google Analytics (UA-XXXXX-X, G-XXXXXXX)
  - Google Tag Manager (GTM-XXXXXXX)
  - Hotjar / FullStory / LuckyOrange (session replay)
  - Segment / Amplitude / Mixpanel (product analytics)
  - Sentry / Datadog / NewRelic (error monitoring)
  - Facebook / Meta Pixel
  - Microsoft Clarity
  - HubSpot tracking
  - LinkedIn Insight Tag
  - Twitter / X Pixel
  - TikTok Pixel
  - Reddit Pixel
  - Pinterest Tag
  - Plausible / Fathom / Umami (privacy analytics)
  - Stripe (payment presence)

Usage:
    from modules.telemetry import extract_telemetry, extract_all
    telemetry = extract_telemetry(body_text)
"""

import re
import json


# ── Regex patterns ──────────────────────────────────────────────────

PATTERNS = {
    # Google
    "ga_ids": re.compile(r'(?:UA-\d{5,}-\d{1,2}|G-[A-Z0-9]{10,12})'),
    "gtm_ids": re.compile(r'GTM-[A-Z0-9]{6,8}'),
    "ga4_ids": re.compile(r'G-[A-Z0-9]{10,12}'),
    "ads_ids": re.compile(r'AW-\d{9,12}'),
    "floodlight_ids": re.compile(r'DC-\d{6,10}'),

    # Session recording / heatmaps
    "has_hotjar": re.compile(r'hotjar', re.I),
    "has_fullstory": re.compile(r'fullstory', re.I),
    "has_luckyorange": re.compile(r'luckyorange|_lto', re.I),
    "has_smartlook": re.compile(r'smartlook', re.I),
    "has_mouseflow": re.compile(r'mouseflow', re.I),
    "has_crazyegg": re.compile(r'crazyegg', re.I),

    # Product analytics
    "has_segment": re.compile(r'segment\.(com|io)|analytics\.js|window\.analytics', re.I),
    "has_amplitude": re.compile(r'amplitude\.com|amplitude\.init|api2\.amplitude', re.I),
    "has_mixpanel": re.compile(r'mixpanel\.com|mixpanel\.init', re.I),
    "has_heap": re.compile(r'heap\.app|heapanalytics', re.I),
    "has_posthog": re.compile(r'posthog\.com|ph\.capture', re.I),

    # Error monitoring
    "has_sentry": re.compile(r'sentry[-.]cdn\.com|@sentry/|sentryDsn|sentry\.io|Sentry\.init', re.I),
    "has_datadog": re.compile(r'datadog|dd_RUM|@datadog', re.I),
    "has_newrelic": re.compile(r'newrelic|NREUM', re.I),
    "has_rollbar": re.compile(r'rollbar\.com|_rollbarConfig', re.I),
    "has_bugsnag": re.compile(r'bugsnag\.com|Bugsnag\.start', re.I),
    "has_logrocket": re.compile(r'logrocket\.com|LogRocket\.init', re.I),

    # Social / Pixels
    "has_fb_pixel": re.compile(r'fbq\s*\(|facebook\.com/tr\?|fb_pixel|\.fb\b', re.I),
    "has_linkedin_insight": re.compile(r'linkedin\.com/trk|_linkedin_partner_id|li_sugr', re.I),
    "has_twitter_pixel": re.compile(r'twitter\.com/beacon|twq\s*\(|analytics\.twitter', re.I),
    "has_tiktok_pixel": re.compile(r'tiktok\.com/pixel|ttq\s*\(|ttq\.track', re.I),
    "has_reddit_pixel": re.compile(r'reddit\.com/static/pixel|rdt\s*\(|redditPixel', re.I),
    "has_pinterest_tag": re.compile(r'pinterest\.com/ct/pinit|pinhtml|pintrk\s*\(', re.I),
    "has_snap_pixel": re.compile(r'snap\.com/chat|snaptr\s*\(|snapchat.*pixel', re.I),

    # Marketing
    "has_hubspot": re.compile(r'hubspot\.com|hs-script-loader|hbspt', re.I),
    "has_marketo": re.compile(r'marketo\.com|mkto.*track', re.I),
    "has_intercom": re.compile(r'intercom\.io|Intercom\(|widget\.intercom', re.I),
    "has_drift": re.compile(r'drift\.com|drift\.load|Drift\s*\(', re.I),

    # Privacy-first analytics
    "has_plausible": re.compile(r'plausible\.io|plausible\.js', re.I),
    "has_fathom": re.compile(r'fathom\.com|cdn\.usefathom', re.I),
    "has_umami": re.compile(r'umami\.is|umami\.js', re.I),

    # Payments
    "has_stripe": re.compile(r'stripe\.com|Stripe\(|stripe\.js', re.I),
    "has_braintree": re.compile(r'braintree|braintree\.js', re.I),

    # CDN / Performance
    "has_cloudflare_analytics": re.compile(r'cloudflare\.com/analytics|cf-analytics', re.I),
    "has_gtmetrix": re.compile(r'gtmetrix|yottaa', re.I),

    # A/B Testing
    "has_optimizely": re.compile(r'optimizely\.com|optimizelyDataFile', re.I),
    "has_vwo": re.compile(r'vwo\.com|_vwo_code', re.I),
    "has_launchdarkly": re.compile(r'launchdarkly\.com|LDClient', re.I),
    "has_google_optimize": re.compile(r'optimize\.google|googleoptimize', re.I),

    # JS Frameworks (helpful for identifying tech stack)
    "has_react": re.compile(r'react\.development|react\.production|__REACT_DEVTOOLS', re.I),
    "has_vue": re.compile(r'vue\.development|vue\.production|__VUE_DEVTOOLS', re.I),
    "has_angular": re.compile(r'angular\.development|angular\.js', re.I),
    "has_jquery": re.compile(r'jquery.*\.js', re.I),
    "has_nextjs": re.compile(r'__NEXT_DATA__|next\.js|_next/static', re.I),
    "has_gatsby": re.compile(r'gatsby\.js|___GATSBY', re.I),

    # API endpoints extracted from JS
    "api_endpoints": re.compile(
        r'https?://[a-zA-Z0-9.-]+\.(?:api|v1|v2|v3|rest|graphql|trpc)'
        r'(?:\.[a-z]+)*/[a-zA-Z0-9/_.-]*'
    ),
    "webhook_urls": re.compile(r'https?://hooks\.(?:slack|zapier|stripe|discord)\.com/'),
}


def extract_telemetry(body):
    """
    Scan an HTML/JS body string for telemetry/analytics services.
    Returns a dict with boolean flags for each service + extracted IDs.
    """
    if not body:
        return {}

    result = {}

    # Simple boolean matches
    for key, pattern in PATTERNS.items():
        if key.startswith("has_"):
            result[key] = bool(pattern.search(body))

    # ID extraction (lists)
    result["ga_ids"] = PATTERNS["ga_ids"].findall(body)
    result["gtm_ids"] = PATTERNS["gtm_ids"].findall(body)
    result["ga4_ids"] = PATTERNS["ga4_ids"].findall(body)
    result["ads_ids"] = PATTERNS["ads_ids"].findall(body)
    result["floodlight_ids"] = PATTERNS["floodlight_ids"].findall(body)

    # API/webhook endpoints found in JS
    result["api_endpoints"] = list(set(PATTERNS["api_endpoints"].findall(body)))
    result["webhook_urls"] = list(set(PATTERNS["webhook_urls"].findall(body)))

    # JS framework version extraction (simple substring)
    if result.pop("has_react", False):
        m = re.search(r'react@(\d+\.\d+\.\d+)', body)
        result["react_version"] = m.group(1) if m else "unknown"
    if result.pop("has_vue", False):
        m = re.search(r'vue@(\d+\.\d+\.\d+)', body)
        result["vue_version"] = m.group(1) if m else "unknown"
    if result.pop("has_jquery", False):
        m = re.search(r'jquery[.-](\d+\.\d+\.\d+)', body)
        result["jquery_version"] = m.group(1) if m else "unknown"
    if result.pop("has_nextjs", False):
        m = re.search(r'__NEXT_DATA__.*?"buildId":"([^"]+)"', body)
        result["next_build_id"] = m.group(1) if m else "unknown"

    return result


def extract_telemetry_from_url(host, port=80, timeout=5, use_https=False):
    """
    Convenience: fetch the page and extract telemetry.
    """
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    scheme = "https" if use_https or port == 443 else "http"
    url = f"{scheme}://{host}:{port}/"

    try:
        r = requests.get(
            url,
            timeout=timeout,
            verify=False,
            headers={"User-Agent": "FLOCK_scan/3.0"},
        )
        return extract_telemetry(r.text)
    except Exception:
        return {}


def summarize_telemetry(telemetry):
    """
    Given a telemetry dict, return a human-readable summary string.
    """
    if not telemetry:
        return "No telemetry data"

    parts = []

    # IDs
    if telemetry.get("ga_ids"):
        parts.append(f"GA: {', '.join(telemetry['ga_ids'])}")
    if telemetry.get("gtm_ids"):
        parts.append(f"GTM: {', '.join(telemetry['gtm_ids'])}")
    if telemetry.get("ads_ids"):
        parts.append(f"Ads: {', '.join(telemetry['ads_ids'])}")

    # Session recording
    for svc in ["hotjar", "fullstory", "luckyorange", "smartlook", "mouseflow"]:
        if telemetry.get(f"has_{svc}"):
            parts.append(svc.title())

    # Product analytics
    for svc in ["segment", "amplitude", "mixpanel", "heap", "posthog"]:
        if telemetry.get(f"has_{svc}"):
            parts.append(svc.title())

    # Error monitoring
    for svc in ["sentry", "datadog", "newrelic", "rollbar", "bugsnag", "logrocket"]:
        if telemetry.get(f"has_{svc}"):
            parts.append(svc.title())

    # Social pixels
    for svc in ["fb_pixel", "linkedin_insight", "twitter_pixel", "tiktok_pixel",
                 "reddit_pixel", "pinterest_tag", "snap_pixel"]:
        if telemetry.get(f"has_{svc}"):
            label = svc.replace("_pixel", "").replace("_tag", "").replace("_insight", "")
            parts.append(f"{label.upper()} pixel")

    # JS framework
    for framework in ["react", "vue", "angular", "nextjs"]:
        key = f"has_{framework}"
        ver_key = f"{framework}_version"
        if telemetry.get(key) or telemetry.get(ver_key):
            ver = telemetry.get(ver_key, "")
            label = framework.title() if not ver else f"{framework.title()} ({ver})"
            parts.append(label)

    if telemetry.get("api_endpoints"):
        parts.append(f"{len(telemetry['api_endpoints'])} API endpoints found")

    return ", ".join(parts) if parts else "None detected"


# ── CLI test ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        target = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
        https = "-s" in sys.argv or "--https" in sys.argv
        result = extract_telemetry_from_url(target, port=port, use_https=https)
        print(json.dumps(result, indent=2, default=str))
        print()
        print("Summary:", summarize_telemetry(result))
    else:
        sample = """
        <script>
          (function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
          (i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
          m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
          })(window,document,'script','https://www.google-analytics.com/analytics.js','ga');
          ga('create', 'UA-12345678-1', 'auto');
          ga('send', 'pageview');
        </script>
        <script>
          !function(f,b,e,v,n,t,s)
          {if(f.fbq)return;n=f.fbq=function(){n.callMethod?
          n.callMethod.apply(n,arguments):n.queue.push(arguments)};
          if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';
          n.queue=[];t=b.createElement(e);t.async=!0;
          t.src=v;s=b.getElementsByTagName(e)[0];
          s.parentNode.insertBefore(t,s)}(window, document,'script',
          'https://connect.facebook.net/en_US/fbevents.js');
          fbq('init', '123456789012345');
          fbq('track', 'PageView');
        </script>
        <script src="https://cdn.segment.com/analytics.js/v1/abc123/analytics.min.js"></script>
        <script src="https://browser.sentry-cdn.com/5.9.1/bundle.min.js"></script>
        <script>
          window.intercomSettings = { app_id: "abc123" };
        </script>
        """
        t = extract_telemetry(sample)
        print(json.dumps(t, indent=2, default=str))
        print()
        print("Summary:", summarize_telemetry(t))
