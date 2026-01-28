from parser import parse_email
from heuristics import PhishingHeuristics

class PhishingClassifier:
    PHISHING_THRESHOLD = 40
    SUSPICIOUS_THRESHOLD = 20

    def __init__(self):
        self.heuristics = PhishingHeuristics()

    def analyze_email(self,sender: str, subject: str, body: str) -> dict:
        parsed_data = parse_email(sender, subject, body)
        text = f"{subject} {body}"
        keyword_results = self.heuristics.keyword_score(text)
        domain_results = self.heuristics.public_domain_score(parsed_data['sender_domain'])
        link_results = self.heuristics.link_score(parsed_data['links'])
        unusual_sender_results = self.heuristics.unusual_sender_score(
            parsed_data["sender_domain"]
        )

        misleading_domain_results = self.heuristics.misleading_domain_score(
            parsed_data["sender_domain"],
            parsed_data["links"])

        total_score = (keyword_results['score'] + domain_results['score'] + link_results['score'] + unusual_sender_results["score"]
            + misleading_domain_results["score"])
        final_score = min(total_score, 100)

        if final_score >=self.PHISHING_THRESHOLD:
            classification = "Phishing"
            severity = "High"
        elif final_score>=self.SUSPICIOUS_THRESHOLD:
            classification = "Suspicious"
            severity = "Medium"
        else:
            classification = "Safe"
            severity = "Low"

        reasons = [keyword_results.get("reason"), domain_results.get("reason"), link_results.get("reason"),
                   unusual_sender_results.get("reason"),misleading_domain_results.get("reason")]
        filtered_reasons = [r for r in reasons if r]

        return {"score": final_score,
                "classification": classification,
                "severity": severity,
                "reasons":filtered_reasons,
                "metadata":{
                    "sender_domain": parsed_data["sender_domain"],
                    "links_found": parsed_data["links_count"]
                    }
                }