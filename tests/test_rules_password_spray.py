from datetime import datetime, timezone
import pytest

from src.models import EventType, UnifiedAuthRecord
from src.rules_password_spray import PasswordSprayRule


def make_auth_record(
    timestamp_epoch: float,
    username: str,
    source_ip: str = "198.51.100.50",
    event_type: EventType = EventType.FAILED_LOGIN,
    hostname: str = "auth-gw01",
) -> UnifiedAuthRecord:
    """Helper to construct standardized UnifiedAuthRecord instances for testing."""
    return UnifiedAuthRecord(
        timestamp=datetime.fromtimestamp(timestamp_epoch, tz=timezone.utc),
        hostname=hostname,
        service="sshd",
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        port=22,
    )


@pytest.fixture
def spray_rule() -> PasswordSprayRule:
    """Provides a fresh PasswordSprayRule instance with lower thresholds for testing."""
    return PasswordSprayRule(
        user_threshold=4,
        window_seconds=120,
        alert_cooldown_seconds=60,
    )


def test_spray_rule_triggers_alert_when_threshold_crossed(spray_rule: PasswordSprayRule):
    """Verify an alert is generated once unique user targets meet or exceed threshold."""
    base_time = 1700000000.0
    users = ["alice", "bob", "charlie", "david"]

    alert = None
    for i, user in enumerate(users):
        record = make_auth_record(base_time + (i * 10.0), username=user)
        alert = spray_rule.evaluate(record)

    assert alert is not None
    assert alert.rule_id == "RULE-PW-SPRAY-001"
    assert alert.mitre_technique == "T1110.003"
    assert alert.severity == "HIGH"
    assert alert.source_ip == "198.51.100.50"
    assert alert.target_users == ["alice", "bob", "charlie", "david"]
    assert alert.event_count == 4
    assert alert.metadata["distinct_targets_count"] == 4


def test_spray_rule_does_not_trigger_on_single_user_repetition(spray_rule: PasswordSprayRule):
    """Verify vertical brute force on one account does not trigger horizontal spray alerts."""
    base_time = 1700000000.0

    alert = None
    for i in range(10):
        record = make_auth_record(base_time + (i * 5.0), username="admin")
        alert = spray_rule.evaluate(record)

    assert alert is None


def test_spray_rule_sliding_window_evicts_stale_records(spray_rule: PasswordSprayRule):
    """Verify events falling outside window_seconds do not count towards threshold."""
    base_time = 1700000000.0

    # 3 unique users at base_time
    assert spray_rule.evaluate(make_auth_record(base_time, "user1")) is None
    assert spray_rule.evaluate(make_auth_record(base_time + 5.0, "user2")) is None
    assert spray_rule.evaluate(make_auth_record(base_time + 10.0, "user3")) is None

    # 4th user arrives 200 seconds later (window_seconds is 120s, previous 3 evicted)
    alert = spray_rule.evaluate(make_auth_record(base_time + 200.0, "user4"))
    assert alert is None


def test_spray_rule_ignores_accepted_logins(spray_rule: PasswordSprayRule):
    """Verify successful logins are ignored and do not count toward spray threshold."""
    base_time = 1700000000.0
    users = ["u1", "u2", "u3", "u4", "u5"]

    alert = None
    for i, u in enumerate(users):
        record = make_auth_record(
            base_time + i,
            username=u,
            event_type=EventType.ACCEPTED_LOGIN,
        )
        alert = spray_rule.evaluate(record)

    assert alert is None


def test_spray_rule_enforces_alert_cooldown(spray_rule: PasswordSprayRule):
    """Verify subsequent spray attempts within cooldown window do not duplicate alerts."""
    base_time = 1700000000.0
    users_batch_1 = ["u1", "u2", "u3", "u4"]

    first_alert = None
    for i, u in enumerate(users_batch_1):
        first_alert = spray_rule.evaluate(make_auth_record(base_time + (i * 2.0), u))
    assert first_alert is not None

    # 5th user arrives 10 seconds later (within alert_cooldown_seconds=60)
    suppressed_alert = spray_rule.evaluate(
        make_auth_record(base_time + 20.0, "u5")
    )
    assert suppressed_alert is None

    # 6th user arrives 70 seconds later (after cooldown expires)
    re_alert = spray_rule.evaluate(
        make_auth_record(base_time + 95.0, "u6")
    )
    assert re_alert is not None
    assert "u6" in re_alert.target_users


def test_spray_rule_process_batch_sorts_and_evaluates(spray_rule: PasswordSprayRule):
    """Verify batch processing handles unordered event streams correctly."""
    base_time = 1700000000.0
    records = [
        make_auth_record(base_time + 30.0, "david"),
        make_auth_record(base_time + 0.0, "alice"),
        make_auth_record(base_time + 20.0, "charlie"),
        make_auth_record(base_time + 10.0, "bob"),
    ]

    alerts = spray_rule.process_batch(records)
    assert len(alerts) == 1
    assert alerts[0].target_users == ["alice", "bob", "charlie", "david"]


def test_spray_rule_reset_clears_internal_state(spray_rule: PasswordSprayRule):
    """Verify reset() empties in-memory history and cooldown timestamps."""
    base_time = 1700000000.0
    for u in ["u1", "u2", "u3", "u4"]:
        spray_rule.evaluate(make_auth_record(base_time, u))

    spray_rule.reset()
    assert len(spray_rule._history) == 0
    assert len(spray_rule._last_alert_time) == 0
    