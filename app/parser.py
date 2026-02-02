import re
from email.utils import parseaddr
from bs4 import BeautifulSoup

# finds URLs in plain text or raw HTML tex
URL_REGEX = r'(?i)\b((?:https?://|www\.)[^\s<>"\']+)'

def extract_urls(text: str) -> list[str]:
    # extracts URLs from free text (body or raw HTML string)
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
    # extracts href links specifically from <a href="..."> tags
    if not html:
        return []
    soup = BeautifulSoup(html, "html.parser")
    out = []
    for a in soup.find_all("a", href=True):
        h = (a.get("href") or "").strip().rstrip(").,;\"'")
        if h.startswith("www."):
            h = "http://" + h
        if h.startswith(("http://", "https://")):
            out.append(h)
    return out

def extract_sender_domain(sender_raw: str) -> str:
    # extracts domain from a From header value
    sender_raw = (sender_raw or "").strip()
    _, email_address = parseaddr(sender_raw)
    if "@" in email_address:
        return email_address.split("@", 1)[-1].lower()
    return ""

def parse_email(sender_raw: str, subject_text: str, body_text: str, body_html: str | None = None) -> dict:
    #  central parser for the detection pipeline

    sender_raw = (sender_raw or "").strip()
    subject_text = (subject_text or "").strip()
    body_text = body_text or ""
    body_html = body_html or ""

    # extract URLs from multiple sources
    urls_plain = extract_urls(body_text)
    urls_html = extract_urls(body_html)
    hrefs = extract_hrefs(body_html)

    # merge while preserving order and removing duplicates
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
