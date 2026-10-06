"""URL feature extraction (ftr_ext.py).

Converts a raw URL into a fixed-order numeric feature vector using only the
URL string itself (lexical + structural + domain attributes). No network
calls are made, so extraction is fast and works on never-seen URLs.
"""
import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlparse

import tldextract

# offline: use the public-suffix snapshot bundled with tldextract
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "update", "secure", "account", "banking",
    "confirm", "password", "paypal", "ebay", "wallet", "suspend", "billing",
    "support", "webscr", "authenticate", "recover", "unlock", "alert",
]
SUSPICIOUS_TLDS = {"zip", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click",
                   "link", "work", "country", "kim", "loan", "support", "icu"}
SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
              "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at"}

FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length", "query_length",
    "num_dots", "num_hyphens", "num_underscores", "num_slashes",
    "num_digits", "num_special_chars", "digit_ratio", "letter_ratio",
    "has_at_symbol", "has_ip_address", "has_port", "uses_https",
    "num_subdomains", "domain_length", "tld_length", "suspicious_tld",
    "domain_hyphens", "domain_digits", "has_punycode", "is_shortener",
    "double_slash_in_path", "suspicious_keyword_count", "domain_entropy",
]


def normalize_url(url: str) -> str:
    url = (url or "").strip()
    if url and not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in Counter(text).values())


def _is_ip(host: str) -> int:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return 1
    except ValueError:
        # also catch decimal/hex encoded hosts like 3232235777 or 0xC0A80001
        return int(bool(re.fullmatch(r"(0x[0-9a-fA-F]+|\d{8,10})", host)))


def extract_features(url: str) -> dict:
    url = normalize_url(url)
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
        port = p.port
    except ValueError:
        p, host, port = urlparse(""), "", None
    ext = _EXTRACT(host)
    domain = ext.domain or ""
    subs = [s for s in ext.subdomain.split(".") if s] if ext.subdomain else []
    lower = url.lower()
    letters = sum(c.isalpha() for c in url)
    digits = sum(c.isdigit() for c in url)
    n = max(len(url), 1)
    reg = ".".join(x for x in (ext.domain, ext.suffix) if x)

    f = {
        "url_length": len(url),
        "hostname_length": len(host),
        "path_length": len(p.path),
        "query_length": len(p.query),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_underscores": url.count("_"),
        "num_slashes": url.count("/"),
        "num_digits": digits,
        "num_special_chars": sum(url.count(c) for c in "?=&%$#!~"),
        "digit_ratio": digits / n,
        "letter_ratio": letters / n,
        "has_at_symbol": int("@" in url),
        "has_ip_address": _is_ip(host),
        "has_port": int(port is not None and port not in (80, 443)),
        "uses_https": int(p.scheme == "https"),
        "num_subdomains": len(subs),
        "domain_length": len(domain),
        "tld_length": len(ext.suffix or ""),
        "suspicious_tld": int((ext.suffix or "").split(".")[-1] in SUSPICIOUS_TLDS),
        "domain_hyphens": domain.count("-"),
        "domain_digits": sum(c.isdigit() for c in domain),
        "has_punycode": int("xn--" in host),
        "is_shortener": int(reg in SHORTENERS),
        "double_slash_in_path": int("//" in url.split("://", 1)[-1]),
        "suspicious_keyword_count": sum(k in lower for k in SUSPICIOUS_KEYWORDS),
        "domain_entropy": _entropy(domain),
    }
    return {k: f[k] for k in FEATURE_NAMES}


def registered_domain(url: str) -> str:
    try:
        host = (urlparse(normalize_url(url)).hostname or "").lower()
    except ValueError:
        host = ""
    e = _EXTRACT(host)
    return ".".join(x for x in (e.domain, e.suffix) if x) or host


def feature_vector(url: str) -> list:
    f = extract_features(url)
    return [f[k] for k in FEATURE_NAMES]


def host_only_url(url: str) -> str:
    """Reduce a URL to scheme+hostname (fixed scheme). Removes dataset artifacts such as
    'legit URLs are bare domains / phishing URLs have paths' and http-vs-https bias."""
    try:
        host = (urlparse(normalize_url(url)).hostname or "").lower()
    except ValueError:
        host = ""
    return "https://" + host
