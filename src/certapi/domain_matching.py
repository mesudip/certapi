def normalize_domain(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def is_wildcard_domain(domain: str) -> bool:
    return normalize_domain(domain).startswith("*.")


def strip_wildcard_prefix(domain: str) -> str:
    domain = normalize_domain(domain)
    if domain.startswith("*."):
        return domain[2:]
    return domain


def split_domain_labels(domain: str) -> list[str]:
    return [label for label in strip_wildcard_prefix(domain).split(".") if label]


def wildcard_candidate_for_domain(domain: str) -> str | None:
    labels = split_domain_labels(domain)
    if len(labels) < 3:
        return None
    return "*." + ".".join(labels[1:])


def domain_matches_cert_domain(cert_domain: str, domain: str) -> bool:
    cert_domain = normalize_domain(cert_domain)
    domain = normalize_domain(domain)
    if not cert_domain or not domain:
        return False
    if cert_domain == domain:
        return True
    if not cert_domain.startswith("*."):
        return False

    suffix = cert_domain[2:]
    domain_labels = [label for label in domain.split(".") if label]
    suffix_labels = [label for label in suffix.split(".") if label]
    return domain.endswith("." + suffix) and len(domain_labels) == len(suffix_labels) + 1
