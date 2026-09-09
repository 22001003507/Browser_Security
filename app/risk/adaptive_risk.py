from __future__ import annotations


def classify_risk(score: float):

    score = max(
        0,
        min(100, float(score)),
    )

    if score < 25:
        return "SAFE"

    if score < 50:
        return "SUSPICIOUS"

    if score < 75:
        return "HIGH RISK"

    return "CRITICAL"


def calculate_adaptive_risk(
    static_probability: float,
    content_points: float = 0,
    behavior_points: float = 0,
):
    """
    static_probability:
        ML probability in the range 0.0 - 1.0

    Content and behavior points:
        additional security evidence.
    """

    ml_score = (
        max(
            0,
            min(
                1,
                static_probability,
            ),
        )
        * 100
    )

    # Weighted combination.
    #
    # ML remains the primary signal.
    # Dynamic evidence modifies the result.

    score = (
        ml_score * 0.65
        + min(content_points, 50) * 0.20
        + min(behavior_points, 50) * 0.15
    )

    # Strong evidence must never be hidden
    # by an unexpectedly low ML score.

    if behavior_points >= 20:
        score = max(
            score,
            50,
        )

    if behavior_points >= 35:
        score = max(
            score,
            75,
        )

    score = max(
        0,
        min(100, score),
    )

    return {
        "score": round(
            score,
            2,
        ),
        "classification": classify_risk(
            score
        ),
    }