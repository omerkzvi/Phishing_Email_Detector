import config
from app.parser import parse_email
from app.heuristics import PhishingHeuristics
from ml.ml_classifier import ml_instance
from enums import Classification, Severity, MLStatus
from models import MlResult, ScanMetadata, ScanResult, EmailRequest



# use floors for critical signals to make sure the ML doesn't
# accidentally suppress strong phishing indicators. This gives us
# a safe minimum score without being too heavy handed with a forced 100.
CRITICAL_FLOORS = config.CRITICAL_FLOORS


class PhishingClassifier:
    """
    phishing detection:
    we parse the email into structured components.
    than we run a rule based heuristics and an ML model
    and produce a final score, classification, severity, reasons and confidence.
    """
    def __init__(self):
        self.heuristics = PhishingHeuristics()
        self.scoring = config.SCORING



    # Public API
    def analyze_email(self, request_data: EmailRequest) -> ScanResult:
        """
        the main entry point.
        Input:
            request_data (EmailRequest): validated request payload (sender, subject, body, html, headers)
        Output:
            ScanResult: final score + classification + severity + reasons + metadata
        """

        # parse email, normalize and extract sender domain + links (plain + html)
        parsed_email = parse_email(
            request_data.sender,
            request_data.subject,
            request_data.body,
            request_data.body_html,
        )

        # Heuristics, generate explainable signal + a heuristic score
        heuristic_summary = self._calculate_heuristics(
            parsed=parsed_email,
            subject=request_data.subject,
            body=request_data.body,
            headers=request_data.headers,
        )

        # ML prediction
        full_text = f"{request_data.subject} {request_data.body}".strip()
        ml_raw = ml_instance.predict(full_text)
        ml_result = MlResult(**ml_raw)      #  **ml_raw "unpacks" a dict into keyword arguments:
                                            # MlResult(**{"ml_score": 78, "confidence": 0.81, "status": "SUCCESS"})
                                            # is the same as MlResult(ml_score=78, confidence=0.81, status="SUCCESS").
                                            # This converts the raw ML dict into a validated Pydantic object with a stable schema.

        # Final score
        final_score, override_reason = self._calculate_final_score(
            heuristic_score=heuristic_summary["score"],
            heuristic_details=heuristic_summary["results"],
            ml=ml_result,
        )

        # Map final score to classification + severity
        class_info = self._classify(final_score)

        # Collect readable reasons from triggered heuristics
        reasons = self._collect_reasons(heuristic_summary["results"])
        if override_reason:
            # Put critical override reason first to make it stand out
            reasons.insert(0, f"CRITICAL: {override_reason}")

        # Confidence calculations
        decision_confidence = self._compute_decision_confidence(
            final_score=final_score,
            classification=class_info["classification"],
        )
        evidence_confidence = self._compute_evidence_confidence(ml_result)
        overall_confidence = self._compute_overall_confidence(decision_confidence, evidence_confidence)

        # Build the final response object
        return self._build_result(
            final_score=final_score,
            classification=class_info["classification"],
            severity=class_info["severity"],
            reasons=reasons,
            parsed=parsed_email,
            heuristic_score=heuristic_summary["score"],
            ml=ml_result,
            decision_conf=decision_confidence,
            evidence_conf=evidence_confidence,
            overall_conf=overall_confidence,
        )



    # Heuristics
    def _calculate_heuristics(self, parsed: dict, subject: str, body: str, headers: dict | None) -> dict:
        """
        Runs all heuristic checks and aggregates their scores.
        Returns:
            {"score": int (0..100), "results": { "<heuristic_name>": {"score": int, "reason": str, ...}}}"""

        text = f"{subject} {body}"

        # Each heuristic returns a dict with at least:
        # score: integer contribution to heuristic score
        # reason: readable explanation

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


        # Sum all heuristic scores
        total_score = 0
        for v in results.values():
            if isinstance(v, dict):
                total_score += int(v.get("score", 0) or 0)

        return {"score": self._clamp_score(total_score), "results": results}



    # Scoring
    def _calculate_final_score(self, heuristic_score: int, heuristic_details: dict, ml: MlResult) -> tuple[int, str]:
        """
           Returns: (final_score, override_reason)
            Base score:  If ML is available: weighted average of ML score and heuristics score.
                         If ML is unavailable: heuristics only.
           Critical floors: If a critical heuristic triggers, enforce a minimum score (floor).
                            Pick the strongest floor if multiple critical heuristics triggered.
           """
        # Base score (ML + heuristics) or fallback to heuristics-only
        if ml.status == MLStatus.SUCCESS and ml.ml_score is not None:
            w_ml = float(self.scoring.ml_weight)
            w_heu = float(self.scoring.heuristic_weight)
            base = int(round((ml.ml_score * w_ml) + (heuristic_score * w_heu)))
            base_score = self._clamp_score(base)
        else:
            base_score = self._clamp_score(heuristic_score)

        # Critical floors: choose the highest floor among triggered critical heuristics
        best_floor = 0
        best_reason = ""

        for key, floor_score in CRITICAL_FLOORS.items():
            check = heuristic_details.get(key, {})
            if not isinstance(check, dict):
                continue

            if int(check.get("score", 0) or 0) > 0:
                # This heuristic triggered; apply its floor
                if int(floor_score) > best_floor:
                    best_floor = int(floor_score)
                    best_reason = check.get("reason") or f"{key} triggered"

        # Enforce the floor if any critical signal triggered
        if best_floor > 0:
            final = max(base_score, best_floor)
            return self._clamp_score(final), best_reason

        return base_score, ""



    def _classify(self, score: int) -> dict:
        """
         Converts numeric score into:
         classification: Safe / Suspicious / Phishing
         severity: Low / Medium / High
         """
        if score >= self.scoring.phishing_threshold:
            return {"classification": Classification.PHISHING, "severity": Severity.HIGH}
        if score >= self.scoring.suspicious_threshold:
            return {"classification": Classification.SUSPICIOUS, "severity": Severity.MEDIUM}
        return {"classification": Classification.SAFE, "severity": Severity.LOW}


    # Reasons
    def _collect_reasons(self, heuristic_results: dict) -> list[str]:
        """
        Collects only non-empty 'reason' strings from heuristic results.
        The final UI will show these explanations to the user.
        """
        reasons: list[str] = []
        for v in (heuristic_results or {}).values():
            if isinstance(v, dict):
                r = v.get("reason") or ""
                if r:
                    reasons.append(r)
        return reasons


    # Confidence
    def _compute_decision_confidence(self, final_score: int, classification: Classification) -> float:
        """
            Decision confidence measures how far the score is from the relevant threshold:
            - PHISHING: farther above phishing_threshold => higher confidence
            - SAFE: farther below suspicious_threshold => higher confidence
            - SUSPICIOUS: by design it's a middle band => fixed ~0.5
            """
        p_thresh = int(self.scoring.phishing_threshold)
        s_thresh = int(self.scoring.suspicious_threshold)

        # Middle category is inherently uncertain
        if classification == Classification.SUSPICIOUS:
            return 0.50

        if classification == Classification.PHISHING:
            # Map score in [phishing_thresh..100] to confidence in [0.2..1.0]
            full_range = max(1, 100 - p_thresh)
            dist = max(0, final_score - p_thresh)
            conf = dist / full_range
        else:  # SAFE:
            # Map score in [0..suspicious_thresh] to confidence in [1.0..0.2] (reverse direction)
            full_range = max(1, s_thresh)
            dist = max(0, s_thresh - final_score)
            conf = dist / full_range

        return round(max(0.20, min(1.0, conf)), 2)

    def _compute_evidence_confidence(self, ml: MlResult) -> float:
        """
        Evidence confidence measures how strong/rich the evidence is.
         If ML succeeded: incorporate ml.confidence into [0.6..1.0]
         If ML unavailable/error: heuristics-only => 0.6 baseline
        """
        if ml.status == MLStatus.SUCCESS and ml.confidence is not None:
            try:
                m = float(ml.confidence)
            except Exception:
                m = 0.0
            m = max(0.0, min(1.0, m))
            # Scale to [0.60..1.00]
            return round(max(0.60, min(1.0, 0.60 + 0.40 * m)), 2)

        return 0.60

    def _compute_overall_confidence(self, decision_c: float, evidence_c: float) -> float:
        """ Overall confidence = simple average of decision confidence and evidence confidence """

        return round(max(0.0, min(1.0, (float(decision_c) + float(evidence_c)) / 2.0)), 2)


    # Response builder
    def _build_result(
        self,
        final_score: int,
        classification: Classification,
        severity: Severity,
        reasons: list[str],
        parsed: dict,
        heuristic_score: int,
        ml: MlResult,
        decision_conf: float,
        evidence_conf: float,
        overall_conf: float,
    ) -> ScanResult:

        """ Builds the final ScanResult object returned from the API """
        metadata = ScanMetadata(
            sender_domain=parsed.get("sender_domain", ""),
            links_found=int(parsed.get("links_count", 0) or 0),
            heuristic_score=int(heuristic_score),
            ml_status=ml.status,
            ml_score=ml.ml_score,
            ml_confidence=float(ml.confidence or 0.0),
            decision_confidence=float(decision_conf),
            evidence_confidence=float(evidence_conf),
            overall_confidence=float(overall_conf),
        )

        return ScanResult(
            score=int(final_score),
            classification=classification,
            severity=severity,
            reasons=reasons,
            metadata=metadata,
        )

    def _clamp_score(self, score: int) -> int:
        """ Clamp the final score to the allowed range (default 0..100) to prevent
        negative values or values > 100 from breaking the API/UI contract """
        return max(self.scoring.min_score, min(self.scoring.max_score, int(score)))
