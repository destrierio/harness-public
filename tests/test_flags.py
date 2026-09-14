import json

from harness.flags import FlagSubmitter, FLAG_RE


def test_regex_needs_a_digit_inside():
    assert FLAG_RE.search("destrier{abc123}")
    assert not FLAG_RE.search("destrier{abcdef}")  # no digit -> not a flag


def test_scan_submits_each_new_flag_once():
    calls = []

    def transport(url, headers, body):
        calls.append((url, json.loads(body)))
        if url.endswith("/flag"):
            return 200, b'{"captured": true}'
        return 200, b"{}"  # event sink

    fs = FlagSubmitter("http://gw/flag", "http://gw/events", "tok", transport=transport)
    out = fs.scan("noise destrier{root_1} more destrier{root_1} and destrier{user_2}")
    assert {r.flag for r in out} == {"destrier{root_1}", "destrier{user_2}"}
    flag_posts = [c for c in calls if c[0].endswith("/flag")]
    assert len(flag_posts) == 2  # deduped


def test_wrong_flag_is_captured_false_not_error():
    def transport(url, headers, body):
        return 200, b'{"captured": false}'

    fs = FlagSubmitter("http://gw/flag", "http://gw/events", "tok", transport=transport)
    r = fs.submit("destrier{nope1}")
    assert r.captured is False


def test_capture_emits_a_claim_event():
    events = []

    def transport(url, headers, body):
        if url.endswith("/events"):
            events.append(json.loads(body))
            return 200, b"{}"
        return 200, b'{"captured": true, "objectiveId": "o1"}'

    fs = FlagSubmitter("http://gw/flag", "http://gw/events", "tok", transport=transport)
    fs.submit("destrier{root_1}")
    assert events and events[0]["type"] == "objective.claimed"
    assert events[0]["flag"] == "destrier{root_1}"


def test_emit_stop_posts_an_agent_stopped_event():
    # The run's real terminal reason is emitted as a trace event, so a gateway/brownout
    # stop is visible instead of looking like a healthy 'agent-exited' (empty stop_reason).
    events = []

    def transport(url, headers, body):
        events.append((url, json.loads(body)))
        return 200, b"{}"

    fs = FlagSubmitter("http://gw/flag", "http://gw/events", "tok", transport=transport)
    fs.emit_stop("upstream_unavailable", turns=12, flags=1, detail="glm-5.3 brownout")
    assert events and events[0][0] == "http://gw/events"
    body = events[0][1]
    assert body["type"] == "agent.stopped"
    assert body["reason"] == "upstream_unavailable"
    assert body["turns"] == 12 and body["flags"] == 1


def test_emit_stop_is_a_noop_without_an_event_endpoint():
    posted = []

    def transport(url, headers, body):
        posted.append(url)
        return 200, b"{}"

    fs = FlagSubmitter("http://gw/flag", "", "tok", transport=transport)
    fs.emit_stop("deadline")  # no endpoint -> nothing posted, no error
    assert posted == []


def test_emit_stop_swallows_transport_errors():
    def transport(url, headers, body):
        raise OSError("event sink down")

    fs = FlagSubmitter("http://gw/flag", "http://gw/events", "tok", transport=transport)
    fs.emit_stop("gateway_error")  # best-effort telemetry must never raise


def test_duplicate_submit_does_not_repost():
    posts = []

    def transport(url, headers, body):
        if url.endswith("/flag"):
            posts.append(1)
        return 200, b'{"captured": true}'

    fs = FlagSubmitter("http://gw/flag", "http://gw/events", "tok", transport=transport)
    fs.submit("destrier{root_1}")
    r2 = fs.submit("destrier{root_1}")
    assert r2.duplicate is True
    assert len(posts) == 1
