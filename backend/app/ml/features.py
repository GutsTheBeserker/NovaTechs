"""Feature definition and client/server topological feature extraction.

Guarantees 100% offline, privacy-preserving feature extraction:
- Zero network requests.
- Zero DNS resolution.
- Zero page downloads or rendering.
- Zero PII or query string retention.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any, Dict, List, Tuple

# The 40 URL and domain topological attributes from Vrbančič et al. (2020)
URL_FEATURE_NAMES: List[str] = [
    "qty_dot_url",
    "qty_hyphen_url",
    "qty_underline_url",
    "qty_slash_url",
    "qty_questionmark_url",
    "qty_equal_url",
    "qty_at_url",
    "qty_and_url",
    "qty_exclamation_url",
    "qty_space_url",
    "qty_tilde_url",
    "qty_comma_url",
    "qty_plus_url",
    "qty_asterisk_url",
    "qty_hashtag_url",
    "qty_dollar_url",
    "qty_percent_url",
    "qty_tld_url",
    "length_url",
    "qty_dot_domain",
    "qty_hyphen_domain",
    "qty_underline_domain",
    "qty_slash_domain",
    "qty_questionmark_domain",
    "qty_equal_domain",
    "qty_at_domain",
    "qty_and_domain",
    "qty_exclamation_domain",
    "qty_space_domain",
    "qty_tilde_domain",
    "qty_comma_domain",
    "qty_plus_domain",
    "qty_asterisk_domain",
    "qty_hashtag_domain",
    "qty_dollar_domain",
    "qty_percent_domain",
    "qty_vowels_domain",
    "domain_length",
    "domain_in_ip",
    "server_client_domain",
]

FEATURE_DESCRIPTIONS: Dict[str, str] = {
    "qty_dot_url": "Quantity of dots ('.') across the entire URL",
    "qty_hyphen_url": "Quantity of hyphens ('-') across the URL",
    "qty_underline_url": "Quantity of underscores ('_') in the URL",
    "qty_slash_url": "Quantity of forward slashes ('/') in the URL",
    "qty_questionmark_url": "Quantity of question marks ('?') in the URL",
    "qty_equal_url": "Quantity of equal signs ('=') in query parameters",
    "qty_at_url": "Presence of '@' character in URL (credential obfuscation)",
    "qty_and_url": "Quantity of ampersands ('&') in query string",
    "qty_exclamation_url": "Quantity of exclamation marks ('!') in URL",
    "qty_space_url": "Quantity of whitespace characters in URL",
    "qty_tilde_url": "Quantity of tildes ('~') in URL path",
    "qty_comma_url": "Quantity of commas (',') in URL",
    "qty_plus_url": "Quantity of plus signs ('+') in URL",
    "qty_asterisk_url": "Quantity of asterisks ('*') in URL",
    "qty_hashtag_url": "Quantity of hash symbols ('#') in URL",
    "qty_dollar_url": "Quantity of dollar signs ('$') in URL",
    "qty_percent_url": "Quantity of percent-encoded sequences ('%')",
    "qty_tld_url": "Count of top-level domain occurrences in URL path/subdomains",
    "length_url": "Total character length of the full URL",
    "qty_dot_domain": "Quantity of dots ('.') in domain name (subdomain nesting)",
    "qty_hyphen_domain": "Quantity of hyphens ('-') in domain name",
    "qty_underline_domain": "Quantity of underscores ('_') in domain name",
    "qty_slash_domain": "Quantity of slashes ('/') within the domain portion",
    "qty_questionmark_domain": "Question marks present in the domain portion",
    "qty_equal_domain": "Equal signs present in the domain portion",
    "qty_at_domain": "'@' symbol within the domain portion",
    "qty_and_domain": "Ampersands present in the domain portion",
    "qty_exclamation_domain": "Exclamation points in the domain portion",
    "qty_space_domain": "Whitespace characters in the domain portion",
    "qty_tilde_domain": "Tilde characters in the domain portion",
    "qty_comma_domain": "Comma characters in the domain portion",
    "qty_plus_domain": "Plus signs in the domain portion",
    "qty_asterisk_domain": "Asterisks in the domain portion",
    "qty_hashtag_domain": "Hash symbols in the domain portion",
    "qty_dollar_domain": "Dollar signs in the domain portion",
    "qty_percent_domain": "Percent signs in the domain portion",
    "qty_vowels_domain": "Count of vowel characters ('a,e,i,o,u') in domain",
    "domain_length": "Character length of the hostname / domain",
    "domain_in_ip": "Binary indicator if hostname is an IPv4 or IPv6 address literal",
    "server_client_domain": "Binary indicator if domain contains 'server' or 'client' keyword",
}

# Regex for IPv4 address literal in hostname
IPV4_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
IPV6_REGEX = re.compile(r"^\[?[0-9a-fA-F:]+\]?$")

COMMON_TLDS = {
    "com", "org", "net", "edu", "gov", "mil", "io", "co", "info", "biz",
    "xyz", "top", "club", "online", "site", "vip", "icu", "app", "dev",
    "uk", "de", "ca", "au", "fr", "ru", "cn", "in", "jp", "br", "nl", "eu"
}


def is_ip_address(host: str) -> bool:
    """Check if host string is an IPv4 or IPv6 literal."""
    if not host:
        return False
    clean = host.strip("[]").split(":")[0]
    if IPV4_REGEX.match(clean):
        parts = clean.split(".")
        return all(0 <= int(p) <= 255 for p in parts if p.isdigit())
    if ":" in clean and IPV6_REGEX.match(clean):
        return True
    return False


def count_tlds(url: str) -> int:
    """Count occurrences of common top-level domain tokens."""
    tokens = re.split(r"[./?#&=_-]", url.lower())
    return sum(1 for token in tokens if token in COMMON_TLDS)


def extract_features_from_url(raw_url: str) -> Dict[str, float]:
    """Extract the 40 topological URL features purely in memory without network requests.

    Args:
        raw_url: The URL string to inspect.

    Returns:
        Dict mapping each feature name to its numerical value.
    """
    if not raw_url:
        return {feat: 0.0 for feat in URL_FEATURE_NAMES}

    # Ensure URL has a scheme for urlparse if missing
    working_url = raw_url.strip()
    if not (working_url.startswith("http://") or working_url.startswith("https://")):
        parsed_test = urllib.parse.urlparse("//" + working_url)
    else:
        parsed_test = urllib.parse.urlparse(working_url)

    netloc = parsed_test.netloc or ""
    # Strip port if present
    host = netloc.split(":")[0].lower() if ":" in netloc else netloc.lower()
    if not host and parsed_test.path and not ("/" in parsed_test.path):
        host = parsed_test.path.lower()

    # Vowels count in domain
    vowels = set("aeiou")
    qty_vowels = sum(1 for ch in host if ch in vowels)

    # Domain in IP
    domain_in_ip_val = 1.0 if is_ip_address(host) else 0.0

    # Server/client in domain
    server_client_val = 1.0 if ("server" in host or "client" in host) else 0.0

    # Character count helper
    def count_chars(text: str, ch: str) -> float:
        return float(text.count(ch))

    features: Dict[str, float] = {
        "qty_dot_url": count_chars(raw_url, "."),
        "qty_hyphen_url": count_chars(raw_url, "-"),
        "qty_underline_url": count_chars(raw_url, "_"),
        "qty_slash_url": count_chars(raw_url, "/"),
        "qty_questionmark_url": count_chars(raw_url, "?"),
        "qty_equal_url": count_chars(raw_url, "="),
        "qty_at_url": count_chars(raw_url, "@"),
        "qty_and_url": count_chars(raw_url, "&"),
        "qty_exclamation_url": count_chars(raw_url, "!"),
        "qty_space_url": count_chars(raw_url, " ") + count_chars(raw_url, "%20"),
        "qty_tilde_url": count_chars(raw_url, "~"),
        "qty_comma_url": count_chars(raw_url, ","),
        "qty_plus_url": count_chars(raw_url, "+"),
        "qty_asterisk_url": count_chars(raw_url, "*"),
        "qty_hashtag_url": count_chars(raw_url, "#"),
        "qty_dollar_url": count_chars(raw_url, "$"),
        "qty_percent_url": count_chars(raw_url, "%"),
        "qty_tld_url": float(max(1, count_tlds(raw_url))),
        "length_url": float(len(raw_url)),
        "qty_dot_domain": count_chars(host, "."),
        "qty_hyphen_domain": count_chars(host, "-"),
        "qty_underline_domain": count_chars(host, "_"),
        "qty_slash_domain": count_chars(host, "/"),
        "qty_questionmark_domain": count_chars(host, "?"),
        "qty_equal_domain": count_chars(host, "="),
        "qty_at_domain": count_chars(host, "@"),
        "qty_and_domain": count_chars(host, "&"),
        "qty_exclamation_domain": count_chars(host, "!"),
        "qty_space_domain": count_chars(host, " "),
        "qty_tilde_domain": count_chars(host, "~"),
        "qty_comma_domain": count_chars(host, ","),
        "qty_plus_domain": count_chars(host, "+"),
        "qty_asterisk_domain": count_chars(host, "*"),
        "qty_hashtag_domain": count_chars(host, "#"),
        "qty_dollar_domain": count_chars(host, "$"),
        "qty_percent_domain": count_chars(host, "%"),
        "qty_vowels_domain": float(qty_vowels),
        "domain_length": float(len(host)),
        "domain_in_ip": domain_in_ip_val,
        "server_client_domain": server_client_val,
    }

    return features


def extract_features_vector(
    input_data: Dict[str, Any] | str
) -> Tuple[List[float], Dict[str, float]]:
    """Convert input (URL string or feature dictionary) into an ordered vector for ML inference.

    Returns:
        Tuple: (ordered_feature_values, feature_dict)
    """
    if isinstance(input_data, str):
        feature_dict = extract_features_from_url(input_data)
    elif isinstance(input_data, dict):
        if "url" in input_data and isinstance(input_data["url"], str):
            feature_dict = extract_features_from_url(input_data["url"])
        else:
            feature_dict = {}
            for name in URL_FEATURE_NAMES:
                val = input_data.get(name, 0.0)
                try:
                    feature_dict[name] = float(val)
                except (ValueError, TypeError):
                    feature_dict[name] = 0.0
    else:
        feature_dict = {feat: 0.0 for feat in URL_FEATURE_NAMES}

    ordered_vector = [feature_dict[feat] for feat in URL_FEATURE_NAMES]
    return ordered_vector, feature_dict
