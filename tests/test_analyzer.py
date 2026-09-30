from vault.analyzer import analyze_password, is_common_password


def test_empty_password_scores_zero():
    r = analyze_password("")
    assert r.score == 0 and r.label == "Very Weak"


def test_common_password_is_very_weak():
    r = analyze_password("password")
    assert r.is_common and r.score <= 5


def test_common_password_variations_detected():
    assert is_common_password("Password123!")
    assert is_common_password("P@ssw0rd")


def test_short_password_capped():
    assert analyze_password("aB3$x").score <= 25


def test_random_long_password_is_very_strong():
    r = analyze_password("k9#Vd2!xQm7$Lp4@")
    assert r.label == "Very Strong" and not r.is_common


def test_repeated_characters_penalised():
    assert analyze_password("aaaaaaaaaaaa1A!").score < analyze_password("aZbYcXdWeV1A!").score


def test_sequences_flagged():
    r = analyze_password("abcd1234XYZ!")
    assert any("sequence" in tip.lower() for tip in r.feedback)


def test_single_class_short_password_capped_at_fair():
    assert analyze_password("qzjxkvbnmwplo").score <= 50


def test_longer_is_not_weaker():
    assert analyze_password("Xk9#mP2$vL7!").score >= analyze_password("Xk9#mP2$").score


def test_score_bounds():
    for pw in ("a", "Tr0ub4dor&3", "x" * 200, "Ünïcödé-Pässwörd-42!"):
        assert 0 <= analyze_password(pw).score <= 100
