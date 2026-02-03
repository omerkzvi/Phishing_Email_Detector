from urllib.parse import urlparse
import re
import config

class PhishingHeuristics:
    """
    rule-based phishing signals (heuristics).

    design goals:
    fast, deterministic checks (good for explainability + UI reasons).
    each method returns a small dict: {"score": int, "reason": str, ...}
    scores are intentionally small/modular so the service layer can sum them, blend with ML ,enforce CRITICAL_FLOORS policy when needed
    """
    def __init__(self):
        # data-driven lists live in config to keep policy separate from logic
        self.suspicious_keywords = config.SUSPICIOUS_KEYWORDS
        self.public_domains = config.PUBLIC_DOMAINS
        self.known_brands = config.COMMON_BRANDS
        self.sensitive_url_keywords = config.SENSITIVE_URL_KEYWORDS
        self.url_shorteners = config.URL_SHORTENERS
        self.suspicious_tlds = config.SUSPICIOUS_TLDS

    # Text based heuristics
    def keyword_score(self, text: str) -> dict:
        """
        detects "pressure/urgency/security" language patterns commonly used in phishing
        score grows by number of matched keywords
        """
        text_lower = (text or "").lower()
        found = [w for w in self.suspicious_keywords if w in text_lower]
        score = min(len(found) * 10, 30)   # cap to avoid dominating other signals
        return {
            "score": score,
            "found": found,
            "reason": f"Suspicious keywords found: {', '.join(found)}" if found else ""
        }

    # Sender-based heuristics
    def public_domain_score(self, domain: str) -> dict:
        """
        low-weight signal: sender comes from a public email provider (gmail/yahoo/...)
        """
        domain = (domain or "").lower()
        if domain in self.public_domains:
            return {"score": 2, "reason": f"Sent from public domain ({domain})"}
        return {"score": 0, "reason": ""}


    def unusual_sender_score(self, domain: str) -> dict:
        """
        detects brand impersonation patterns in sender domain
        """
        domain = (domain or "").lower()
        for brand in self.known_brands:
            if brand in domain and not domain.startswith(brand):
                if f"{brand}-" in domain or f"-{brand}" in domain:
                    return {
                        "score": 20,
                        "reason": f"Sender domain looks like impersonation of {brand} ({domain})"
                    }
        return {"score": 0, "reason": ""}


    # Link-based heuristics
    def misleading_domain_score(self, sender_domain: str, links: list[str]) -> dict:

        """ email contains a sensitive URL whose domain doesn't match sender domain"""
        sender_domain = (sender_domain or "").lower()
        if not sender_domain:
            return {"score": 0, "reason": ""}

        for link in links or []:
            try:
                parsed = urlparse(link)
                link_domain = (parsed.netloc or "").lower()

                # look for sensitive intent (login/verify/account/...)
                url_text = f"{parsed.path} {parsed.query}".lower()
                is_sensitive = any(k in url_text for k in self.sensitive_url_keywords)

                # mismatch check: sender domain is not within link domain
                mismatch = sender_domain not in link_domain

                if is_sensitive and mismatch:
                    return {
                        "score": 35,
                        "reason": f"Sensitive link domain ({link_domain}) does not match sender domain ({sender_domain})"
                    }
            except Exception:
                # If parsing fails, we skip that URL
                continue

        return {"score": 0, "reason": ""}


    def link_score(self, links: list[str]) -> dict:
        """ too many links can indicate phishing or spam """
        count = len(links or [])
        if count > 3:
            return {"score": 10, "count": count, "reason": f"Many links found: {count}"}
        return {"score": 0, "count": count, "reason": ""}


    def url_shortener_score(self, links: list[str]) -> dict:
        """ detects URL shortness (bit.ly, t.co...) often used to hide destination """

        hits = []
        for link in links or []:
            host = self._host(link)
            if not host:
                continue
            for s in self.url_shorteners:
                if host == s or host.endswith("." + s):
                    hits.append(host)
                    break
        if hits:
            return {"score": 10, "reason": f"Shortened link detected: {', '.join(sorted(set(hits)))}"}
        return {"score": 0, "reason": ""}


    def punycode_score(self, links: list[str]) -> dict:
        """ detects punycode (xn--) which can indicate IDN spoofing """

        hits = []
        for link in links or []:
            host = self._host(link)
            if host and "xn--" in host:
                hits.append(host)
        if hits:
            return {"score": 10, "reason": f"Punycode domain detected: {', '.join(sorted(set(hits)))}"}
        return {"score": 0, "reason": ""}



    def ip_url_score(self, links: list[str]) -> dict:

        """ detects IP-based URLs (rare for legit login pages) """
        hits = []
        for link in links or []:
            host = self._host(link)
            if host and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
                hits.append(host)
        if hits:
            return {"score": 10, "reason": f"IP-based URL detected: {', '.join(sorted(set(hits)))}"}
        return {"score": 0, "reason": ""}

    def at_symbol_url_score(self, links: list[str]) -> dict:
        """detects '@' inside URLs (classic obfuscation trick) """
        hits = []
        for link in links or []:
            if "@" in (link or ""):
                hits.append(link)
        if hits:
            return {"score": 10, "reason": "URL contains '@' (possible obfuscation)"}
        return {"score": 0, "reason": ""}

    def many_dashes_domain_score(self, links: list[str]) -> dict:
        """detects domains with many dashes (often seen in throwaway phishing domains)."""
        hits = []
        for link in links or []:
            host = self._host(link)
            if not host:
                continue
            dash_count = host.count("-")
            if dash_count >= 4:
                hits.append(host)
        if hits:
            return {"score": 10, "reason": f"Suspicious domain (many dashes): {', '.join(sorted(set(hits)))}"}
        return {"score": 0, "reason": ""}

    def suspicious_tld_score(self, links: list[str]) -> dict:
        """detects suspicious TLDs (zip/top/xyz/click...)"""
        hits = []
        for link in links or []:
            host = self._host(link)
            if not host or "." not in host:
                continue
            tld = host.rsplit(".", 1)[-1]
            if tld in self.suspicious_tlds:
                hits.append(host)
        if hits:
            return {"score": 10, "reason": f"Suspicious TLD detected: {', '.join(sorted(set(hits)))}"}
        return {"score": 0, "reason": ""}


    # Header-based heuristics

    def reply_to_mismatch_score(self, sender_domain: str, headers: dict | None) -> dict:
        """ detects Reply-To domain mismatch with sender domain """
        sender_domain = (sender_domain or "").lower()
        if not sender_domain or not headers:
            return {"score": 0, "reason": ""}

        reply_to = self._get_header(headers, "Reply-To")
        if not reply_to:
            return {"score": 0, "reason": ""}

        reply_domain = self._extract_domain_from_header_value(reply_to)
        if reply_domain and reply_domain != sender_domain:
            return {
                "score": 15,
                "reason": f"Reply-To domain ({reply_domain}) differs from sender domain ({sender_domain})"
            }
        return {"score": 0, "reason": ""}


    # Helpers
    def _host(self, url: str) -> str:
        """ extracts normalized hosts from URLs: strips ports, strips 'www.' """
        try:
            p = urlparse(url or "")
            host = (p.netloc or "").lower()
            # strip port
            host = host.split(":")[0]
            # strip common prefix
            if host.startswith("www."):
                host = host[4:]
            return host
        except Exception:
            return ""

    def _get_header(self, headers: dict, name: str) -> str:
        # headers can come as dict of name->value, or dict with "headers" list
        if isinstance(headers, dict):
            # if already flat
            if name in headers and isinstance(headers[name], str):
                return headers[name]
            # common: {"From": "...", "Subject": "..."} etc.
            for k, v in headers.items():
                if k.lower() == name.lower() and isinstance(v, str):
                    return v

        return ""

    def _extract_domain_from_header_value(self, value: str) -> str:
        # Extracts domain from a header containing an email address
        if not value:
            return ""
        m = re.search(r"@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})", value)
        return m.group(1).lower() if m else ""
