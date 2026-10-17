"""AC-3: known_hosts(5) grammar parsing, valid and broken cases."""

from __future__ import annotations

from pathlib import Path

from ssh_id_doctor.domain import KnownHostEntry, UnresolvedItem
from ssh_id_doctor.inspectors.known_hosts import parse_known_hosts

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "known_hosts" / "grammar_cases.txt"

_ED25519_FINGERPRINT = "SHA256:8z2Fpm6wsI4ebPXiQEZAY3BcDDx0XrSASx7FJsZkorg"
_RSA_FINGERPRINT = "SHA256:fEkv9SCAR5/6nQG/lrL9hYk4yccNPFa5mtq+XXdeLMQ"
_ECDSA_FINGERPRINT = "SHA256:16kaGO4v0U+U3KqxCkcm4fOFE7TA7wQOx5r1xHg47o4"
_UNKNOWN_ALGO_FINGERPRINT = "SHA256:c8yjN2G0xcy+BAw3rlf8ghp/H6nhuPdN9csNr8cJfwA"


def _line_of(lines: list[str], marker: str) -> int:
    return next(i for i, text in enumerate(lines, start=1) if marker in text)


def test_parse_grammar_cases() -> None:
    text = FIXTURE.read_text()
    lines = text.splitlines()
    source_file = str(FIXTURE)

    result = parse_known_hosts(text, source_file)

    entries_by_line = {e.line: e for e in result.entries}
    unresolved_by_line = {u.source_line: u for u in result.unresolved}

    # --- valid entries ---

    plain = entries_by_line[_line_of(lines, "valid-ed25519")]
    assert plain == KnownHostEntry(
        source_file=source_file,
        line=plain.line,
        marker=None,
        hosts=("example.com",),
        hashed=False,
        key_type="ssh-ed25519",
        fingerprint=_ED25519_FINGERPRINT,
    )

    revoked = entries_by_line[_line_of(lines, "valid-revoked")]
    assert revoked.marker == "revoked"
    assert revoked.hosts == ("revoked.example.com",)
    assert revoked.fingerprint == _ED25519_FINGERPRINT

    cert_authority = entries_by_line[_line_of(lines, "valid-cert-authority-rsa")]
    assert cert_authority.marker == "cert-authority"
    assert cert_authority.key_type == "ssh-rsa"
    assert cert_authority.fingerprint == _RSA_FINGERPRINT

    host_list = entries_by_line[_line_of(lines, "valid-host-list")]
    assert host_list.marker is None
    assert host_list.hosts == (
        "[git.example.com]:2222",
        "!old.example.com",
        "*.wild.example.com",
    )
    assert host_list.hashed is False
    assert host_list.fingerprint == _RSA_FINGERPRINT

    hashed = entries_by_line[_line_of(lines, "valid-hashed-host")]
    assert hashed.hashed is True
    assert hashed.hosts == ("|1|AAECAwQFBgcICQoLDA0ODxAREhM=|FBUWFxgZGhscHR4fICEiIyQlJic=",)
    assert hashed.fingerprint == _ED25519_FINGERPRINT

    ecdsa = entries_by_line[_line_of(lines, "valid-ecdsa")]
    assert ecdsa.key_type == "ecdsa-sha2-nistp256"
    assert ecdsa.fingerprint == _ECDSA_FINGERPRINT

    unknown_algo = entries_by_line[_line_of(lines, "valid-unknown-algo")]
    assert unknown_algo.key_type == "ssh-unknown-type"
    assert unknown_algo.fingerprint == _UNKNOWN_ALGO_FINGERPRINT

    # --- broken lines: UnresolvedItem, no quoted line content ---

    bad_markers = {
        "bad-unknown-marker": "unknown_marker",
        "bad-hashed-salt-length": "invalid_hosts_field",
        "bad-mismatched-curve": "invalid_key_blob",
        "bad-blob-type-only": "invalid_key_blob",
        "bad-blob-extra-bytes": "invalid_key_blob",
        "bad-base64": "invalid_base64",
        "bad-hosts-field": "invalid_hosts_field",
    }
    for comment, expected_kind in bad_markers.items():
        lineno = _line_of(lines, comment)
        item = unresolved_by_line[lineno]
        assert item == UnresolvedItem(
            kind=expected_kind,
            detail="",
            source_file=source_file,
            source_line=lineno,
        )
        assert comment not in item.detail
        assert comment not in item.kind

    incomplete = next(
        u for u in result.unresolved if lines[u.source_line - 1].startswith("incomplete.")
    )
    assert incomplete.kind == "incomplete_line"
    assert incomplete.detail == ""

    # Nothing from a broken line's raw text leaks into kind/detail anywhere.
    all_text = " ".join(f"{u.kind}{u.detail}" for u in result.unresolved)
    assert "example.com" not in all_text
    assert "AAAA" not in all_text
