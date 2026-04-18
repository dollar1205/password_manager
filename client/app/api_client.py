from __future__ import annotations

from typing import Any

import httpx

from .config import APP_VERSION


class ApiError(RuntimeError):
    pass


class VersionConflictError(ApiError):
    def __init__(self, current_version: int, message: str):
        super().__init__(message)
        self.current_version = current_version


class ServerApiClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.timeout = httpx.Timeout(10.0, connect=5.0, read=10.0, write=10.0)

    def register(self) -> dict[str, Any]:
        return self._request(
            "POST",
            "/register",
            json_payload={"client_version": APP_VERSION},
        )

    def fetch_vault(self, api_token: str) -> dict[str, Any]:
        return self._request("GET", "/vault", api_token=api_token)

    def upload_vault(
        self,
        api_token: str,
        encrypted_vault: str,
        base_version: int,
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            "/upload",
            api_token=api_token,
            json_payload={
                "encrypted_vault": encrypted_vault,
                "base_version": base_version,
                "client_version": APP_VERSION,
            },
        )

    def _request(
        self,
        method: str,
        path: str,
        *,
        api_token: str | None = None,
        json_payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        headers = {
            "Accept": "application/json",
            "Cache-Control": "no-store",
        }
        if api_token:
            headers["Authorization"] = f"Bearer {api_token}"

        try:
            with httpx.Client(
                base_url=self.base_url,
                timeout=self.timeout,
                follow_redirects=False,
            ) as client:
                response = client.request(method, path, json=json_payload, headers=headers)
        except httpx.HTTPError as exc:
            raise ApiError(f"Network error: {exc}") from exc

        if response.status_code == 409:
            detail = self._parse_error_detail(response)
            if isinstance(detail, dict):
                current_version = int(detail.get("current_version", -1))
                message = str(detail.get("message", "Vault version conflict."))
            else:
                current_version = -1
                message = str(detail or "Vault version conflict.")
            raise VersionConflictError(current_version=current_version, message=message)

        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ApiError(self._format_error_message(response)) from exc

        try:
            return response.json()
        except ValueError as exc:
            raise ApiError("Server returned invalid JSON.") from exc

    @staticmethod
    def _parse_error_detail(response: httpx.Response) -> Any:
        try:
            payload = response.json()
        except ValueError:
            return response.text
        return payload.get("detail", payload)

    def _format_error_message(self, response: httpx.Response) -> str:
        detail = self._parse_error_detail(response)
        if isinstance(detail, dict):
            message = detail.get("message")
            if message:
                return str(message)
        if isinstance(detail, str) and detail.strip():
            return detail.strip()
        return f"Unexpected server response: HTTP {response.status_code}"
