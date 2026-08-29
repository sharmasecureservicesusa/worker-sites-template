from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.db import get_session
from app.models import Member, Resource
from app.routers.oauth import load_bearer_member

router = APIRouter()


def member_payload(member: Member) -> dict:
    return {
        "id": member.id,
        "email": member.email,
        "display_name": member.display_name,
        "role": member.role,
        "email_verified": member.email_verified,
        "created_at": member.created_at.isoformat(),
    }


@router.get("/api/me")
def me(request: Request, session: Session = Depends(get_session)):
    member = getattr(request.state, "member", None) or load_bearer_member(request, session)
    if member is None:
        return JSONResponse({"detail": "Authentication required"}, status_code=401)
    return member_payload(member)


@router.get("/api/members")
def members(request: Request, session: Session = Depends(get_session)):
    rows = session.scalars(select(Member).where(Member.is_active.is_(True)).order_by(Member.display_name)).all()
    return [
        {
            "display_name": row.display_name,
            "email": row.email,
            "role": row.role,
            "created_at": row.created_at.isoformat(),
        }
        for row in rows
    ]


@router.get("/api/resources")
def resources(session: Session = Depends(get_session)):
    rows = session.scalars(select(Resource).order_by(Resource.title)).all()
    return [
        {"slug": row.slug, "title": row.title, "summary": row.summary}
        for row in rows
    ]


@router.get("/api/resources/{slug}")
def resource(slug: str, session: Session = Depends(get_session)):
    row = session.scalar(select(Resource).where(Resource.slug == slug))
    if row is None:
        return JSONResponse({"detail": "Not found"}, status_code=404)
    return {"slug": row.slug, "title": row.title, "summary": row.summary, "body": row.body}


@router.get("/api/history")
def history(session: Session = Depends(get_session)):
    rows = session.execute(
        text("SELECT commit_hash, committer, email, date, message FROM dolt_log LIMIT 40")
    ).all()
    return [
        {
            "commit_hash": row.commit_hash,
            "committer": row.committer,
            "email": row.email,
            "date": str(row.date),
            "message": row.message,
        }
        for row in rows
    ]
