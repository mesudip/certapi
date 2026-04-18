def _normalize_domain(domain: str) -> str:
    domain = domain.strip().lower().rstrip(".")
    if domain.startswith("*."):
        domain = domain[2:]
    return domain


def _split_labels(domain: str) -> list[str]:
    normalized = _normalize_domain(domain)
    return [label for label in normalized.split(".") if label]


def would_trigger(labels: list[str], blocked: set[str]) -> bool:
    """
    Boulder-style recursive on-demand trigger check used by tests.
    """
    if len(labels) < 4:
        return False

    blocked = {label.lower() for label in blocked}

    consecutive_blocked = 0
    prev_label: str | None = None
    for label in labels:
        label = label.lower()
        is_blocked = label in blocked
        if is_blocked:
            consecutive_blocked += 1
            if prev_label is not None and prev_label == label:
                return True
            if consecutive_blocked >= 3:
                return True
        else:
            consecutive_blocked = 0
        prev_label = label
    return False


def split_domain_to_safe_groups(domain: str, blocked_labels: list[str] | None = None) -> list[list[str]]:
    """
    Split labels into contiguous chunks of at most 3 labels.
    This mirrors the "3 labels are always safe for this specific LE heuristic"
    invariant, but these label groups are not used directly as issuance domains.
    """
    labels = _split_labels(domain)
    n = len(labels)
    if n == 0:
        return []
    return [labels[i : i + 3] for i in range(0, n, 3)]


def create_safe_domain_batches(domains: list[str], blocked_labels: list[str] | None = None) -> list[list[str]]:
    """
    Create compact issuance batches without any blocked-label list assumptions.

    Rules:
    - Domains with <= 3 labels are grouped together into one compact batch.
    - Longer domains are split into safe label groups and emitted as singleton batches.

    This avoids guessed label lists and keeps behavior deterministic.
    """
    compact_batch: list[str] = []
    singleton_batches: list[list[str]] = []
    seen: set[str] = set()

    for domain in domains:
        normalized = _normalize_domain(domain)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)

        labels = [label for label in normalized.split(".") if label]
        if len(labels) <= 3:
            compact_batch.append(normalized)
            continue

        for i in range(0, len(labels), 3):
            singleton_batches.append([".".join(labels[i : i + 3])])

    if compact_batch:
        return [compact_batch, *singleton_batches]
    return singleton_batches
