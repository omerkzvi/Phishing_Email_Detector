import config
from app.parser import parse_email
from app.heuristics import PhishingHeuristics
from ml.ml_classifier import ml_instance
from enums import Classification, Severity, MLStatus
from models import MlResult, ScanMetadata, ScanResult, EmailRequest


class PhishingClassifier:
    def __init__(self):
        self.heuristics = PhishingHeuristics()
        self.scoring = config.SCORING

    def analyze_email(self, request_data: EmailRequest) -> ScanResult:
        parsed = parse_email(
            request_data.sender,
            request_data.subject,
            request_data.body,
            request_data.body_html,
        )

        heuristic = self._calculate_heuristics(
            parsed=parsed,
            subject=request_data.subject,
            body=request_data.body,
            headers=request_data.headers,
        )

        ml_raw = ml_instance.predict(f"{request_data.subject} {request_data.body}".strip())
        ml_result = MlResult(**ml_raw)

        final_score = self._final_score(heuristic_score=heuristic["score"], ml=ml_result)
        class_info = self._classify(final_score)
        reasons = self._collect_reasons(heuristic["results"])

        decision_confidence = self._compute_decision_confidence(
            final_score=final_score,
            classification=class_info["classification"],
        )
        evidence_confidence = self._compute_evidence_confidence(
            heuristic_score=heuristic["score"],
            ml=ml_result,
        )
        overall_confidence = self._compute_overall_confidence(
            classification=class_info["classification"],
            decision_confidence=decision_confidence,
            evidence_confidence=evidence_confidence,
        )

        return self._build_result(
            final_score=final_score,
            classification=class_info["classification"],
            severity=class_info["severity"],
            reasons=reasons,
            parsed=parsed,
            heuristic_score=heuristic["score"],
            ml=ml_result,
            decision_confidence=decision_confidence,
            evidence_confidence=evidence_confidence,
            overall_confidence=overall_confidence,
        )

    def _calculate_heuristics(self, parsed: dict, subject: str, body: str, headers: dict | None) -> dict:
        text = f"{subject} {body}"

        results = {
            "keyword": self.heuristics.keyword_score(text),
            "public_domain": self.heuristics.public_domain_score(parsed["sender_domain"]),
            "links": self.heuristics.link_score(parsed["links"]),
            "unusual_sender": self.heuristics.unusual_sender_score(parsed["sender_domain"]),
            "misleading_domain": self.heuristics.misleading_domain_score(parsed["sender_domain"], parsed["links"]),

            "url_shortener": self.heuristics.url_shortener_score(parsed["links"]),
            "punycode": self.heuristics.punycode_score(parsed["links"]),
            "ip_url": self.heuristics.ip_url_score(parsed["links"]),
            "at_symbol_url": self.heuristics.at_symbol_url_score(parsed["links"]),
            "many_dashes": self.heuristics.many_dashes_domain_score(parsed["links"]),
            "suspicious_tld": self.heuristics.suspicious_tld_score(parsed["links"]),

            "reply_to_mismatch": self.heuristics.reply_to_mismatch_score(parsed["sender_domain"], headers),
        }

        score = sum(int(v.get("score", 0) or 0) for v in results.values())
        return {"score": self._clamp_score(score), "results": results}

    def _final_score(self, heuristic_score: int, ml: MlResult) -> int:
        if ml.status == MLStatus.SUCCESS and ml.ml_score is not None:
            score = (self.scoring.ml_weight * ml.ml_score) + (self.scoring.heuristic_weight * heuristic_score)
            score_int = int(round(score))
        else:
            score_int = int(heuristic_score)

        return self._clamp_score(score_int)

    def _classify(self, score: int) -> dict:
        if score >= self.scoring.phishing_threshold:
            return {"classification": Classification.PHISHING, "severity": Severity.HIGH}
        if score >= self.scoring.suspicious_threshold:
            return {"classification": Classification.SUSPICIOUS, "severity": Severity.MEDIUM}
        return {"classification": Classification.SAFE, "severity": Severity.LOW}

    def _collect_reasons(self, heuristic_results: dict) -> list[str]:
        reasons = []
        for v in (heuristic_results or {}).values():
            r = v.get("reason") if isinstance(v, dict) else ""
            if r:
                reasons.append(r)
        return reasons

    # -------------------------
    # Option A: Confidence split
    # -------------------------

    def _compute_decision_confidence(self, final_score: int, classification: Classification) -> float:
        p = float(self.scoring.phishing_threshold)
        s = float(self.scoring.suspicious_threshold)
        margin = 20.0

        if classification == Classification.PHISHING:
            conf = (final_score - p) / margin
            return round(max(0.0, min(1.0, conf)), 2)

        if classification == Classification.SAFE:
            conf = (s - final_score) / margin
            return round(max(0.0, min(1.0, conf)), 2)

        band_low = s
        band_high = max(s, p - 1.0)
        if band_high <= band_low:
            return 0.5

        mid = (band_low + band_high) / 2.0
        half = (band_high - band_low) / 2.0
        conf = 1.0 - (abs(final_score - mid) / half)
        return round(max(0.0, min(1.0, conf)), 2)

    def _compute_evidence_confidence(self, heuristic_score: int, ml: MlResult) -> float:
        h = max(0.0, min(1.0, float(heuristic_score) / 100.0))

        if ml.status == MLStatus.SUCCESS and ml.ml_score is not None:
            m = max(0.0, min(1.0, float(ml.confidence)))

            ml_phishy = ml.ml_score >= self.scoring.suspicious_threshold
            h_phishy = heuristic_score >= self.scoring.suspicious_threshold
            agreement = 1.0 if (ml_phishy == h_phishy) else 0.4

            ev = (0.45 * m) + (0.45 * h) + (0.10 * agreement)
            return round(max(0.0, min(1.0, ev)), 2)

        ev = (0.9 * h) + (0.1 * 0.5)
        return round(max(0.0, min(1.0, ev)), 2)

    def _compute_overall_confidence(
        self,
        classification: Classification,
        decision_confidence: float,
        evidence_confidence: float,
    ) -> float:
        # classification-aware weights:
        # - PHISHING: evidence matters more
        # - SAFE: decision sharpness matters more
        # - SUSPICIOUS: balanced
        if classification == Classification.PHISHING:
            w_dec, w_evid = 0.35, 0.65
        elif classification == Classification.SAFE:
            w_dec, w_evid = 0.75, 0.25
        else:  # SUSPICIOUS
            w_dec, w_evid = 0.55, 0.45

        overall = (w_dec * float(decision_confidence)) + (w_evid * float(evidence_confidence))
        return round(max(0.0, min(1.0, overall)), 2)

    # -------------------------
    # Build response
    # -------------------------

    def _build_result(
        self,
        final_score: int,
        classification: Classification,
        severity: Severity,
        reasons: list[str],
        parsed: dict,
        heuristic_score: int,
        ml: MlResult,
        decision_confidence: float,
        evidence_confidence: float,
        overall_confidence: float,
    ) -> ScanResult:
        metadata = ScanMetadata(
            sender_domain=parsed["sender_domain"],
            links_found=parsed["links_count"],
            heuristic_score=heuristic_score,
            ml_status=ml.status,
            ml_score=ml.ml_score,
            ml_confidence=ml.confidence,
            decision_confidence=decision_confidence,
            evidence_confidence=evidence_confidence,
            overall_confidence=overall_confidence,
        )

        return ScanResult(
            score=final_score,
            classification=classification,
            severity=severity,
            reasons=reasons,
            metadata=metadata,
        )

    def _clamp_score(self, score: int) -> int:
        return max(self.scoring.min_score, min(self.scoring.max_score, int(score)))
