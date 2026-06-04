"""Tests for app/security/http_logging — safe HTTP diagnostics."""

from __future__ import annotations

import httpx

from app.security.http_logging import json_key_summary, response_metadata


class TestResponseMetadata:
    def test_shape(self):
        resp = httpx.Response(401, json={"error": "invalid_token", "access_token": "SECRET"})
        meta = response_metadata(resp)
        assert meta["status_code"] == 401
        assert meta["body_len"] == len(resp.content)
        assert len(meta["body_sha256_8"]) == 8

    def test_never_exposes_body_values(self):
        secret = "super-secret-refresh-token"
        resp = httpx.Response(400, json={"refresh_token": secret})
        meta = response_metadata(resp)
        assert secret not in str(meta)

    def test_content_type_included(self):
        resp = httpx.Response(200, json={}, headers={"content-type": "application/scim+json"})
        assert response_metadata(resp)["content_type"] == "application/scim+json"

    def test_hash_is_deterministic(self):
        resp = httpx.Response(200, content=b"same body")
        assert response_metadata(resp)["body_sha256_8"] == response_metadata(resp)["body_sha256_8"]

    def test_different_bodies_different_hash(self):
        r1 = httpx.Response(200, content=b"body one")
        r2 = httpx.Response(200, content=b"body two")
        assert response_metadata(r1)["body_sha256_8"] != response_metadata(r2)["body_sha256_8"]


class TestJsonKeySummary:
    def test_never_exposes_values(self):
        data = {"access_token": "SECRET", "refresh_token": "ALSO_SECRET"}
        summary = json_key_summary(data)
        assert "SECRET" not in summary
        assert "ALSO_SECRET" not in summary

    def test_keys_present(self):
        data = {"access_token": "x", "expires_in": 3600}
        summary = json_key_summary(data)
        assert "access_token" in summary
        assert "expires_in" in summary

    def test_keys_sorted(self):
        data = {"z_key": 1, "a_key": 2, "m_key": 3}
        summary = json_key_summary(data)
        assert summary == "object_keys=['a_key', 'm_key', 'z_key']"

    def test_list_input(self):
        summary = json_key_summary([1, 2, 3])
        assert summary == "list_len=3"

    def test_other_type(self):
        assert json_key_summary("plain string") == "type=str"
        assert json_key_summary(42) == "type=int"

    def test_empty_dict(self):
        assert json_key_summary({}) == "object_keys=[]"
