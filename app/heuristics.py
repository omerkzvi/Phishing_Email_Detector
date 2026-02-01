from urllib.parse import urlparse
import re
import config

class PhishingHeuristics:
    def __init__(self):
        self.suspicious_keywords = config.SUSPICIOUS_KEYWORDS
        self.public_domains = config.PUBLIC_DOMAINS
        self.known_brands = config.COMMON_BRANDS
        self.sensitive_url_keywords = config.SENSITIVE_URL_KEYWORDS
        self.url_shorteners = config.URL_SHORTENERS
        self.suspicious_tlds = config.SUSPICIOUS_TLDS

    def keyword_score(self, text: str) -> dict:
        text_lower = (text or "").lower()
        found = [w for w in self.suspicious_keywords if w in text_lower]
        score = min(len(found) * 10, 30)
        return {
            "score": score,
            "found": found,
            "reason": f"Suspicious keywords found: {', '.join(found)}" if found else ""
        }

    def public_domain_score(self, domain: str) -> dict:
        domain = (domain or "").lower()
        if domain in self.public_domains:
            return {"score": 10, "reason": f"Sent from public domain ({domain})"}
        return {"score": 0, "reason": ""}

    def unusual_sender_score(self, domain: str) -> dict:
        domain = (domain or "").lower()
        for brand in self.known_brands:
            if brand in domain and not domain.startswith(brand):
                if f"{brand}-" in domain or f"-{brand}" in domain:
                    return {
                        "score": 20,
                        "reason": f"Sender domain looks like impersonation of {brand} ({domain})"
                    }
        return {"score": 0, "reason": ""}

    def misleading_domain_score(self, sender_domain: str, links: list[str]) -> dict:
        sender_domain = (sender_domain or "").lower()
        if not sender_domain:
            return {"score": 0, "reason": ""}

        for link in links or []:
            try:
                parsed = urlparse(link)
                link_domain = (parsed.netloc or "").lower()
                url_text = f"{parsed.path} {parsed.query}".lower()

                is_sensitive = any(k in url_text for k in self.sensitive_url_keywords)
                mismatch = sender_domain not in link_domain

                if is_sensitive and mismatch:
                    return {
                        "score": 35,
                        "reason": f"Sensitive link domain ({link_domain}) does not match sender domain ({sender_domain})"
                    }
            except Exception:
                continue

        return {"score": 0, "reason": ""}

    def link_score(self, links: list[str]) -> dict:
        count = len(links or [])
        if count > 3:
            return {"score": 10, "count": count, "reason": f"Many links found: {count}"}
        return {"score": 0, "count": count, "reason": ""}

    # -------------------------
    # New: URL-focused heuristics (server-side source of truth)
    # -------------------------
    def url_shortener_score(self, links: list[str]) -> dict:
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
        hits = []
        for link in links or []:
            host = self._host(link)
            if host and "xn--" in host:
                hits.append(host)
        if hits:
            return {"score": 10, "reason": f"Punycode domain detected: {', '.join(sorted(set(hits)))}"}
        return {"score": 0, "reason": ""}

    def ip_url_score(self, links: list[str]) -> dict:
        hits = []
        for link in links or []:
            host = self._host(link)
            if host and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
                hits.append(host)
        if hits:
            return {"score": 10, "reason": f"IP-based URL detected: {', '.join(sorted(set(hits)))}"}
        return {"score": 0, "reason": ""}

    def at_symbol_url_score(self, links: list[str]) -> dict:
        hits = []
        for link in links or []:
            if "@" in (link or ""):
                hits.append(link)
        if hits:
            return {"score": 10, "reason": "URL contains '@' (possible obfuscation)"}
        return {"score": 0, "reason": ""}

    def many_dashes_domain_score(self, links: list[str]) -> dict:
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

    # -------------------------
    # New: Reply-To mismatch (headers-driven)
    # -------------------------
    def reply_to_mismatch_score(self, sender_domain: str, headers: dict | None) -> dict:
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

    # -------------------------
    # Helpers
    # -------------------------
    def _host(self, url: str) -> str:
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
        # very lightweight: find last @domain pattern
        if not value:
            return ""
        m = re.search(r"@([A-Za-z0-9\.\-]+\.[A-Za-z]{2,})", value)
        return (m.group(1).lower() if m else "")
