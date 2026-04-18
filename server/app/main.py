from __future__ import annotations

from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .auth import get_current_record
from .config import get_settings
from .db import get_db, init_db
from .models import VaultRecord, utcnow
from .schemas import RegisterRequest, RegisterResponse, UploadRequest, UploadResponse, VaultResponse
from .security import decoded_base64_length, generate_api_token, generate_salt_b64, hash_api_token

settings = get_settings()
limiter = Limiter(key_func=get_remote_address, default_limits=[settings.default_rate_limit])


def _request_proto(request: Request) -> str:
    forwarded_proto = request.headers.get("x-forwarded-proto")
    if forwarded_proto:
        return forwarded_proto.split(",")[0].strip().lower()
    return request.url.scheme.lower()


def _is_local_request(request: Request) -> bool:
    host = (request.url.hostname or "").lower()
    return host in {"127.0.0.1", "localhost", "::1"}


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

    @app.on_event("startup")
    def startup() -> None:
        init_db()

    @app.middleware("http")
    async def apply_security_headers(request: Request, call_next):
        proto = _request_proto(request)
        if settings.require_https and proto != "https":
            if not (settings.allow_insecure_localhost and _is_local_request(request)):
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"detail": "HTTPS is required for this API."},
                )

        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        if proto == "https":
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        return response

    @app.get("/health")
    def healthcheck() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
    @limiter.limit(settings.register_rate_limit)
    def register(
        request: Request,
        payload: RegisterRequest,
        db: Session = Depends(get_db),
    ) -> RegisterResponse:
        for _ in range(5):
            user_id = str(uuid4())
            api_token = generate_api_token(settings.token_prefix, settings.token_bytes)
            record = VaultRecord(
                user_id=user_id,
                token_hash=hash_api_token(api_token),
                salt_b64=generate_salt_b64(settings.salt_bytes),
                encrypted_vault_b64=None,
                vault_version=0,
            )
            db.add(record)
            try:
                db.commit()
                db.refresh(record)
                return RegisterResponse(
                    user_id=record.user_id,
                    salt=record.salt_b64,
                    api_token=api_token,
                    vault_version=record.vault_version,
                    updated_at=record.updated_at,
                )
            except IntegrityError:
                db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to allocate a unique token. Try again.",
        )

    @app.post("/upload", response_model=UploadResponse)
    @limiter.limit(settings.upload_rate_limit)
    def upload_vault(
        request: Request,
        payload: UploadRequest,
        current_record: VaultRecord = Depends(get_current_record),
        db: Session = Depends(get_db),
    ) -> UploadResponse:
        decoded_length = decoded_base64_length(payload.encrypted_vault)
        if decoded_length > settings.max_vault_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Encrypted vault exceeds {settings.max_vault_bytes} bytes.",
            )

        if payload.base_version != current_record.vault_version:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "message": "Vault version conflict.",
                    "current_version": current_record.vault_version,
                },
            )

        current_record.encrypted_vault_b64 = payload.encrypted_vault
        current_record.vault_version += 1
        current_record.updated_at = utcnow()
        db.add(current_record)
        db.commit()
        db.refresh(current_record)

        return UploadResponse(
            vault_version=current_record.vault_version,
            updated_at=current_record.updated_at,
        )

    @app.get("/vault", response_model=VaultResponse)
    @limiter.limit(settings.vault_rate_limit)
    def get_vault(
        request: Request,
        current_record: VaultRecord = Depends(get_current_record),
    ) -> VaultResponse:
        return VaultResponse(
            salt=current_record.salt_b64,
            encrypted_vault=current_record.encrypted_vault_b64,
            vault_version=current_record.vault_version,
            updated_at=current_record.updated_at,
        )

    return app


app = create_app()
