import re
from email.utils import parseaddr

URL_REGEX = r'(?i)\b((?:https?://|www\.)[^\s<>"\']+)'
HREF_REGEX = r'(?i)href\s*=\s*["\']([^"\']+)["\']'

def extract_urls(text: str) -> list[str]:
    if not text:
        return []

    urls = re.findall(URL_REGEX, text)
    clean_urls = []
    for url in urls:
        url = url.strip().rstrip(").,;\"'")
        if url.startswith("www."):
            url = "http://" + url
        clean_urls.append(url)
    return clean_urls

def extract_hrefs(html: str) -> list[str]:
    if not html:
        return []
    hrefs = re.findall(HREF_REGEX, html)
    clean = []
    for h in hrefs:
        h = (h or "").strip().rstrip(").,;\"'")
        if h.startswith("www."):
            h = "http://" + h
        if h.startswith("http://") or h.startswith("https://"):
            clean.append(h)
    return clean

def extract_sender_domain(sender_raw: str) -> str:
    sender_raw = (sender_raw or "").strip()
    _, email_address = parseaddr(sender_raw)
    if "@" in email_address:
        return email_address.split("@", 1)[-1].lower()
    return ""

def parse_email(sender_raw: str, subject_text: str, body_text: str, body_html: str | None = None) -> dict:
    sender_raw = (sender_raw or "").strip()
    subject_text = (subject_text or "").strip()
    body_text = body_text or ""
    body_html = body_html or ""

    urls_plain = extract_urls(body_text)
    urls_html = extract_urls(body_html)
    hrefs = extract_hrefs(body_html)

    # union while preserving order-ish
    links = []
    for u in (urls_plain + urls_html + hrefs):
        if u and u not in links:
            links.append(u)

    return {
        "sender": sender_raw,
        "sender_domain": extract_sender_domain(sender_raw),
        "subject": subject_text,
        "body": body_text,
        "body_html": body_html,
        "links": links,
        "links_count": len(links),
    }
