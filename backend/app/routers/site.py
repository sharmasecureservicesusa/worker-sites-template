from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_session
from app.models import Member, Resource
from app.routers.auth import NOTICE
from app.templating import templates

router = APIRouter()


def page(request: Request, name: str, status_code: int = 200, **context):
    member = request.state.member
    return templates.TemplateResponse(
        request,
        name,
        {
            "member": member,
            "settings": get_settings(),
            "notice": NOTICE.get(request.query_params.get("notice", ""), ""),
            **context,
        },
        status_code=status_code,
    )


@router.get("/")
def home():
    return RedirectResponse("/dashboard", status_code=303)


@router.get("/dashboard")
def dashboard(request: Request, session: Session = Depends(get_session)):
    roster_count = len(session.scalars(select(Member).where(Member.is_active.is_(True))).all())
    resources = session.scalars(select(Resource).order_by(Resource.title)).all()
    return page(
        request,
        "dashboard.html",
        section="dashboard",
        roster_count=roster_count,
        resources=resources,
    )


@router.get("/directory")
def directory(request: Request, session: Session = Depends(get_session)):
    members = session.scalars(
        select(Member).where(Member.is_active.is_(True)).order_by(Member.display_name)
    ).all()
    return page(request, "directory.html", section="directory", members=members)


@router.get("/library")
def library(request: Request, session: Session = Depends(get_session)):
    resources = session.scalars(select(Resource).order_by(Resource.title)).all()
    return page(request, "library.html", section="library", resources=resources)


@router.get("/library/{slug}")
def resource_detail(request: Request, slug: str, session: Session = Depends(get_session)):
    resource = session.scalar(select(Resource).where(Resource.slug == slug))
    if resource is None:
        return page(request, "not_found.html", section="library", status_code=404)
    return page(request, "resource.html", section="library", resource=resource)


@router.get("/history")
def history(request: Request, session: Session = Depends(get_session)):
    commits = session.execute(
        text("SELECT commit_hash, committer, email, date, message FROM dolt_log LIMIT 40")
    ).all()
    return page(request, "history.html", section="history", commits=commits)


@router.get("/profile")
def profile(request: Request):
    return page(request, "profile.html", section="profile")
