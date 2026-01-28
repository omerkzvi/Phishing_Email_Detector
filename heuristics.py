from urllib.parse import urlparse

class PhishingHeuristics:

    def __init__(self):
        self.suspicious_keywords = [
            "urgent", "verify", "password", "bank", "suspended",
            "click here", "immediate action", "security alert"
        ]

        self.public_domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]
        self.common_brands = ["paypal", "google", "amazon", "facebook", "apple"]


    def keyword_score(self, text: str) -> dict:
        found = [w for w in self.suspicious_keywords if w in text.lower()]
        score = min(len(found)*10 , 30)
        return {"score": score,
                "found": found,
                "reason": f"Suspicious keywords found: {', '.join(found)}" if found else ""}


    def public_domain_score(self, domain:str) -> dict:
        if domain in self.public_domains:
            return {"score": 10,
                    "reason": f"sent from public domain ({domain})"}

        return {"score": 0, "reason": ""}

    def unusual_sender_score(self, domain: str) -> dict:
        for brand in self.common_brands:
            if brand in domain and not domain.startswith(brand):
                return {
                    "score": 20,
                    "reason": f"Sender domain looks like a fake {brand} domain ({domain})"
                }
        return {"score": 0, "reason": ""}


    def misleading_domain_score(self, sender_domain: str, links: list[str]) -> dict:
        for link in links:
            link_domain = urlparse(link).netloc.lower()
            if sender_domain not in link_domain:
                return {
                    "score": 20,
                    "reason": f"Link domain ({link_domain}) does not match sender domain ({sender_domain})"
                }
        return {"score": 0, "reason": ""}


    def link_score(self, links:list[str])-> dict:
        count = len(links)
        return {"score": 20 if count > 0 else 0,
                "count": count,
                "reason": f"{count} suspicious links found" if count > 0 else ""}
