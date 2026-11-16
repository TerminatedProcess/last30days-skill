"""Tests for Linux Chromium-family (Vivaldi) cookie extraction."""

import shutil
from unittest import mock

import pytest

from lib import chrome_cookies, cookie_extract
from lib.chrome_cookies import (
    LINUX_PBKDF2_ITERATIONS,
    LINUX_V10_PASSWORD,
    _derive_aes_key,
    extract_chromium_browser_cookies_linux,
)
from tests.test_chrome_cookies import _create_chrome_cookies_db, _encrypt_value_v10

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl required")

KEYRING_PW = b"dummy-keyring-password"
V11_KEY = _derive_aes_key(KEYRING_PW, LINUX_PBKDF2_ITERATIONS)
V10_KEY = _derive_aes_key(LINUX_V10_PASSWORD, LINUX_PBKDF2_ITERATIONS)


def _v11(plaintext: str) -> bytes:
    return b"v11" + _encrypt_value_v10(plaintext, V11_KEY)[3:]


def _vivaldi_profile(tmp_path, rows, db_version=24):
    base = tmp_path / "vivaldi"
    (base / "Default").mkdir(parents=True)
    _create_chrome_cookies_db(str(base / "Default" / "Cookies"), rows, db_version=db_version)
    return base


def _patch_registry(base):
    spec = (base, (("Chrome Keys", "Chrome Safe Storage"),), ("chrome",))
    return mock.patch.dict(chrome_cookies.LINUX_CHROMIUM_BROWSERS, {"vivaldi": spec})


def test_v11_cookies_decrypt_with_keyring_password(tmp_path):
    # db_version < 24: no SHA-256 prefix to strip.
    base = _vivaldi_profile(tmp_path, [
        (".x.com", "auth_token", "", _v11("tok123")),
        (".x.com", "ct0", "", _v11("csrf456")),
    ], db_version=20)
    with _patch_registry(base), mock.patch.object(
        chrome_cookies, "_get_linux_keyring_passwords", return_value=[KEYRING_PW]
    ) as kr:
        got = extract_chromium_browser_cookies_linux("vivaldi", ".x.com", ["auth_token", "ct0"])
    assert got == {"auth_token": "tok123", "ct0": "csrf456"}
    assert kr.call_count == 1  # keyring read once, not per cookie


def test_v10_cookies_use_peanuts_without_keyring(tmp_path):
    base = _vivaldi_profile(tmp_path, [
        (".x.com", "ct0", "", _encrypt_value_v10("plain-v10", V10_KEY)),
    ], db_version=20)
    with _patch_registry(base), mock.patch.object(
        chrome_cookies, "_get_linux_keyring_passwords"
    ) as kr:
        got = extract_chromium_browser_cookies_linux("vivaldi", ".x.com", ["ct0"])
    assert got == {"ct0": "plain-v10"}
    kr.assert_not_called()


def test_no_keyring_password_returns_none(tmp_path):
    base = _vivaldi_profile(tmp_path, [(".x.com", "ct0", "", _v11("x"))])
    with _patch_registry(base), mock.patch.object(
        chrome_cookies, "_get_linux_keyring_passwords", return_value=[]
    ):
        assert extract_chromium_browser_cookies_linux("vivaldi", ".x.com", ["ct0"]) is None


def test_keyring_lookup_prefers_kwallet_then_libsecret():
    calls = []

    def fake(args, timeout=30):
        calls.append(args[0])
        return "from-secret-tool" if args[0] == "secret-tool" else None

    with mock.patch.object(chrome_cookies, "_run_secret_cli", side_effect=fake):
        pws = chrome_cookies._get_linux_keyring_passwords(
            (("Chrome Keys", "Chrome Safe Storage"),), ("chrome",)
        )
    assert pws == [b"from-secret-tool"]
    assert calls == ["kwallet-query", "secret-tool"]


def test_kwallet_missing_folder_notice_is_not_a_password():
    with mock.patch.object(
        chrome_cookies, "_run_secret_cli",
        side_effect=lambda args, timeout=30: "The folder Chrome Keys does not exist!"
        if args[0] == "kwallet-query" else None,
    ):
        assert chrome_cookies._get_linux_keyring_passwords(
            (("Chrome Keys", "Chrome Safe Storage"),), ()
        ) == []


def test_wrong_first_keyring_password_falls_through_to_the_right_one(tmp_path):
    # e.g. a stale Chrome entry in KWallet ahead of Vivaldi's real password.
    base = _vivaldi_profile(tmp_path, [
        (".x.com", "auth_token", "", _v11("tok123")),
        (".x.com", "ct0", "", _v11("csrf456")),
    ], db_version=20)
    with _patch_registry(base), mock.patch.object(
        chrome_cookies, "_get_linux_keyring_passwords",
        return_value=[b"some-other-browsers-password", KEYRING_PW],
    ):
        got = extract_chromium_browser_cookies_linux("vivaldi", ".x.com", ["auth_token", "ct0"])
    assert got == {"auth_token": "tok123", "ct0": "csrf456"}


def test_cookie_extract_routes_vivaldi_on_linux_and_auto_order():
    with mock.patch.object(cookie_extract.platform, "system", return_value="Linux"), \
         mock.patch.object(chrome_cookies, "extract_chromium_browser_cookies_linux",
                           return_value={"ct0": "v"}) as linux, \
         mock.patch.object(cookie_extract, "_extract_firefox_with_source", return_value=None):
        assert cookie_extract.extract_cookies_with_source("vivaldi", ".x.com", ["ct0"]) == ({"ct0": "v"}, "vivaldi")
        assert cookie_extract.extract_cookies_with_source("auto", ".x.com", ["ct0"]) == ({"ct0": "v"}, "vivaldi")
    assert linux.call_count == 2


def test_other_chromium_browsers_still_unsupported_on_linux():
    with mock.patch.object(cookie_extract.platform, "system", return_value="Linux"):
        assert cookie_extract.extract_cookies("edge", ".x.com", ["ct0"]) is None
