import re

URL_REGEX = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'

def extract_links(text: str) -> list[str]:
    return re.findall(URL_REGEX, text)

def extract_domain(sender_email:str) -> str:
    if "@" in sender_email:
        return sender_email.split("@")[-1].lower()
    return ""

def parse_email(sender: str, subject: str, body: str) -> dict:
    links = extract_links(body)
    return {
        "sender": sender,
        "sender_domain": extract_domain(sender),
        "subject": subject,
        "body": body,
        "links": links,
        "links_count": len(links)
    }