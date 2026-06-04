import sys

import pytest

import p0rtix


def test_parse_targets_file_ignores_comments_and_supports_optional_fields(tmp_path):
    targets_file = tmp_path / "targets.txt"
    targets_file.write_text(
        "\n"
        "# IP [domain [name]]\n"
        "10.0.0.5 example.internal dc01\n"
        "10.0.0.6\n"
        "10.0.0.7 example2.internal\n"
    )

    assert p0rtix._parse_targets_file(str(targets_file)) == [
        ("10.0.0.5", "example.internal", "dc01"),
        ("10.0.0.6", None, None),
        ("10.0.0.7", "example2.internal", None),
    ]


def test_parse_args_rejects_ip_and_targets_together(monkeypatch, tmp_path):
    targets_file = tmp_path / "targets.txt"
    targets_file.write_text("10.0.0.5\n")
    monkeypatch.setattr(sys, "argv", ["p0rtix.py", "10.0.0.5", "--targets", str(targets_file)])

    with pytest.raises(SystemExit):
        p0rtix.parse_args()


def test_parse_args_accepts_credential_placeholders_for_creds_mode(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "p0rtix.py",
            "10.0.0.5",
            "--domain",
            "example.internal",
            "--mode",
            "creds",
            "-u",
            "<USERNAME>",
            "-p",
            "<PASSWORD>",
        ],
    )

    args = p0rtix.parse_args()

    assert args.ip == "10.0.0.5"
    assert args.domain == "example.internal"
    assert args.mode == "creds"
    assert args.username == "<USERNAME>"
    assert args.password == "<PASSWORD>"
