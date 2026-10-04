"""Count exposed Polaris triage fields without retaining their values in reports."""

FIELDS = ("triage status", "set-by", "set-at", "status history")
_ALIASES = {
    "status": "triage status",
    "triagestatus": "triage status",
    "setby": "set-by",
    "statussetby": "set-by",
    "triagesetby": "set-by",
    "setat": "set-at",
    "statussetat": "set-at",
    "triagesetat": "set-at",
    "statushistory": "status history",
    "triagestatushistory": "status history",
    "history": "status history",
}


def _field(key: str, *, top_level: bool = False) -> str | None:
    normalized = "".join(c.lower() for c in key if c.isalnum())
    if top_level and normalized in {"status", "setby", "setat", "history"}:
        return None
    return _ALIASES.get(normalized)


def _entries(issue: dict):
    for prop in issue.get("triageProperties") or []:
        if isinstance(prop, dict) and isinstance(prop.get("key"), str):
            yield prop["key"], prop.get("value"), False
    triage = issue.get("triage")
    if isinstance(triage, dict):
        for key, value in triage.items():
            yield key, value, False
    for key, value in issue.items():
        yield key, value, True


def report(issues: list[dict]) -> dict:
    exposed = {field: False for field in FIELDS}
    counts = {field: 0 for field in FIELDS}
    for issue in issues:
        populated = set()
        for key, value, top_level in _entries(issue):
            field = _field(key, top_level=top_level)
            if field:
                exposed[field] = True
                if value is not None and value != "" and value != [] and value != {}:
                    populated.add(field)
        for field in populated:
            counts[field] += 1
    return {"issues_examined": len(issues), "fields": {
        field: {"presence": "present" if exposed[field] else "absent", "issues": counts[field]}
        for field in FIELDS
    }}
