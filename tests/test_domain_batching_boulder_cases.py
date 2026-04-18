from certapi.domain_batching import would_trigger


def _looks_like_recursive_on_demand_request_test_only(idents, blocked):
    if not blocked:
        return False

    blocked_set = {label.lower() for label in blocked}
    for ident in idents or []:
        if ident.get("type") != "dns":
            continue
        labels = [label for label in ident["value"].lower().split(".") if label]
        if would_trigger(labels, blocked_set):
            return True
    return False


def test_looks_like_recursive_on_demand_request_boulder_cases():
    test_cases = [
        {
            "name": "no blocks",
            "idents": [{"type": "dns", "value": "example.com"}],
            "blocked": None,
            "want_err": False,
        },
        {
            "name": "no idents",
            "idents": None,
            "blocked": ["asdf"],
            "want_err": False,
        },
        {
            "name": "no dns idents",
            "idents": [{"type": "ip", "value": "1.2.3.4"}],
            "blocked": ["asdf"],
            "want_err": False,
        },
        {
            "name": "short idents",
            "idents": [
                {"type": "dns", "value": "foo.example.com"},
                {"type": "dns", "value": "bar.example.com"},
            ],
            "blocked": ["asdf"],
            "want_err": False,
        },
        {
            "name": "long but not blocked ident",
            "idents": [
                {"type": "dns", "value": "foo.example.com"},
                {"type": "dns", "value": "asdf.qwer.zxcv.asdf.example.com"},
            ],
            "blocked": ["asdf"],
            "want_err": False,
        },
        {
            "name": "two identical blocked labels early",
            "idents": [
                {"type": "dns", "value": "foo.example.com"},
                {"type": "dns", "value": "asdf.asdf.qwer.zxcv.example.com"},
            ],
            "blocked": ["asdf"],
            "want_err": True,
        },
        {
            "name": "two identical blocked labels late",
            "idents": [
                {"type": "dns", "value": "foo.example.com"},
                {"type": "dns", "value": "qwer.zxcv.asdf.asdf.example.com"},
            ],
            "blocked": ["asdf"],
            "want_err": True,
        },
        {
            "name": "three blocked labels",
            "idents": [
                {"type": "dns", "value": "foo.example.com"},
                {"type": "dns", "value": "asdf.qwer.zxcv.asdf.example.com"},
            ],
            "blocked": ["asdf", "qwer", "zxcv"],
            "want_err": True,
        },
    ]

    for tc in test_cases:
        got = _looks_like_recursive_on_demand_request_test_only(tc["idents"], tc["blocked"])
        assert got is tc["want_err"], f"{tc['name']}: got={got} want={tc['want_err']}"
