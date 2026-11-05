import csv

from securaai_ml.wazuh_review import payload_to_review_row, review_suggestion, review_to_model_frame, validate_review_csv, write_review_csv


def test_suggestion_is_not_a_training_label():
    assert review_suggestion({"wazuh_rule_level": 12}) == "REVIEW_MALICIOUS_CANDIDATE"
    assert review_suggestion({"wazuh_rule_level": 3, "event_id": "4624"}) == "REVIEW_BENIGN_CANDIDATE"
    assert review_suggestion({"wazuh_rule_level": 5, "event_type": "LOGIN_FAILURE"}) == "REVIEW_REQUIRED"


def test_payload_mapping_keeps_reviewer_fields_empty():
    row = payload_to_review_row({"external_event_id": "real-1", "account_identifier": "review-user", "severity": "3", "event_type": "LOGIN_SUCCESS", "normalized_payload": {"metadata": {"eventId": "4624"}}})
    assert row["event_id"] == "4624"
    assert row["account_identifier"] == "review-user"
    assert row["reviewer_label"] == ""
    assert row["include_for_training"] == "false"


def test_write_and_validate_review_csv(tmp_path):
    path = tmp_path / "review.csv"
    write_review_csv([{"external_event_id": "x", "normalized_payload": {}}], path)
    with path.open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    rows[0]["include_for_training"], rows[0]["reviewer_label"] = "true", "BENIGN"
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys()); writer.writeheader(); writer.writerows(rows)
    assert validate_review_csv(path) == (1, 0)


def test_review_to_model_frame_maps_authentication_fields():
    frame = review_to_model_frame(__import__('pandas').DataFrame([{
        'occurred_at': '2026-11-02T16:15:05Z', 'event_id': '4625',
        'provider_name': 'Microsoft-Windows-Security-Auditing', 'channel': 'Security',
        'logon_type': '3', 'authentication_package': 'NTLM', 'source_ip': '127.0.0.1',
        'command_line_present': 'false', 'hashes_present': 'false',
    }]))
    assert frame.loc[0, 'event_id'] == '4625'
    assert frame.loc[0, 'auth_package'] == 'ntlm'
    assert frame.loc[0, 'source_ip_private'] == 1
