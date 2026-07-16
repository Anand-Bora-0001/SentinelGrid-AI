"""
SentinelGrid AI — Main FastAPI Application
Detect. Predict. Contain. Recover.
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import os
import asyncio
import logging

# Configuration (must be first — sets up logging and directories)
from .config import settings

logger = logging.getLogger(__name__)

# ========================
# APP FACTORY
# ========================

app = FastAPI(
    title=settings.app_name,
    description="SentinelGrid AI — Production-Grade AI-Powered Cyber Resilience Platform for Critical National Infrastructure",
    version=settings.app_version,
    debug=settings.debug
)

# ========================
# CORS MIDDLEWARE
# ========================

allowed_origins = ["*"] if not os.getenv("RENDER") else [
    "http://localhost:5173",
    "http://localhost:3000",
    os.getenv("FRONTEND_URL", "https://sentinelgrid-frontend.onrender.com"),
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# ========================
# MOUNT ROUTERS
# ========================

from .api.routes.auth import router as auth_router
from .api.routes.telemetry import router as telemetry_router
from .api.routes.incidents import router as incidents_router
from .api.routes.mitre import router as mitre_router
from .api.routes.predictions import router as predictions_router
from .api.routes.vulnerabilities import router as vulnerabilities_router
from .api.routes.assets import router as assets_router
from .api.routes.response import router as response_router
from .api.routes.audit import router as audit_router
from .api.routes.health import router as health_router
from .api.routes.anomaly import router as anomaly_router
from .api.routes.threat_intel import router as threat_intel_router

app.include_router(auth_router)
app.include_router(telemetry_router)
app.include_router(incidents_router)
app.include_router(mitre_router)
app.include_router(predictions_router)
app.include_router(vulnerabilities_router)
app.include_router(assets_router)
app.include_router(response_router)
app.include_router(audit_router)
app.include_router(health_router)
app.include_router(anomaly_router)
app.include_router(threat_intel_router)

# ========================
# STARTUP / SHUTDOWN
# ========================

@app.on_event("startup")
async def startup_event():
    logger.info(f" Starting {settings.app_name} v{settings.app_version}")
    logger.info(f" Environment: {'Development' if settings.debug else 'Production'}")

    # Initialize database
    try:
        from .database import init_db
        init_db()
        logger.info(" Database initialized")
    except Exception as e:
        logger.error(f" Database init failed: {e}")

    # Seed initial assets and vulnerabilities if db is empty
    try:
        from .database import get_db
        from .models import Asset, User
        from .auth import ensure_demo_users_in_db
        db = next(get_db())
        # Ensure demo users & org exist first
        ensure_demo_users_in_db(db)
        
        # Check if assets exist
        asset_count = db.query(Asset).count()
        if asset_count == 0:
            logger.info(" Seeding initial CNI asset topology...")
            from .services.simulation_engine import simulation_engine
            from .models import Organization
            org = db.query(Organization).first()
            if org:
                # Seed assets
                for asset_data in simulation_engine.get_seed_assets():
                    asset = Asset(organization_id=org.id, **asset_data)
                    db.add(asset)
                db.commit()
                logger.info(" Assets seeded successfully")
                
                # Seed vulnerabilities
                from .models import Vulnerability
                assets_map = {a.name: a.id for a in db.query(Asset).filter(Asset.organization_id == org.id).all()}
                for vuln_data in simulation_engine.get_seed_vulnerabilities():
                    v = Vulnerability(
                        organization_id=org.id,
                        cve_id=vuln_data["cve_id"],
                        title=vuln_data["title"],
                        cvss_score=vuln_data["cvss_score"],
                        severity=vuln_data["severity"],
                        exploit_available=vuln_data["exploit_available"],
                        exploit_maturity=vuln_data.get("exploit_maturity"),
                        affected_asset_id=assets_map.get(vuln_data.get("affected_asset")),
                        business_impact=vuln_data["business_impact"],
                        affected_component=vuln_data.get("affected_component"),
                    )
                    db.add(v)
                db.commit()
                logger.info(" Vulnerabilities seeded successfully")
    except Exception as e:
        logger.error(f" Startup seeding failed: {e}")

    logger.info(f" API Docs: http://{settings.host}:{settings.port}/docs")


# ========================
# FRONTEND STATIC FILES
# ========================

_BACKEND_DIR = Path(__file__).resolve().parent.parent
_PROJECT_DIR = _BACKEND_DIR.parent
_FRONTEND_DIR = _PROJECT_DIR / "frontend"
_FRONTEND_DIST = _FRONTEND_DIR / "dist"

if _FRONTEND_DIST.exists():
    logger.info(f"Serving compiled React frontend from: {_FRONTEND_DIST}")
    # Mount assets folder for static files
    if (_FRONTEND_DIST / "assets").exists():
        app.mount("/assets", StaticFiles(directory=str(_FRONTEND_DIST / "assets")), name="frontend_assets")
        
    @app.get("/{catchall:path}")
    async def serve_react_app(catchall: str):
        # If it asks for an API path that doesn't exist, return 404
        if catchall.startswith("api/") or catchall.startswith("auth/") or catchall == "health":
            raise HTTPException(status_code=404, detail="API Endpoint not found")
        # Otherwise serve index.html for React Router SPA routes
        index_file = _FRONTEND_DIST / "index.html"
        if index_file.exists():
            return FileResponse(str(index_file))
        raise HTTPException(status_code=404, detail="React app index.html not found")
        
elif _FRONTEND_DIR.exists() and (_FRONTEND_DIR / "login.html").exists():
    logger.info(f"Serving vanilla HTML/CSS fallback from: {_FRONTEND_DIR}")
    app.mount("/css", StaticFiles(directory=str(_FRONTEND_DIR / "css")), name="frontend_css")
    app.mount("/js", StaticFiles(directory=str(_FRONTEND_DIR / "js")), name="frontend_js")
    if (_FRONTEND_DIR / "assets").exists():
        app.mount("/assets", StaticFiles(directory=str(_FRONTEND_DIR / "assets")), name="frontend_assets")
    app.mount("/static", StaticFiles(directory=str(_FRONTEND_DIR)), name="frontend_static")

    @app.get("/")
    async def root():
        return FileResponse(str(_FRONTEND_DIR / "index.html"))

    @app.get("/login.html")
    async def serve_login():
        return FileResponse(str(_FRONTEND_DIR / "login.html"))

    @app.get("/dashboard.html")
    async def serve_dashboard():
        return FileResponse(str(_FRONTEND_DIR / "dashboard.html"))

    @app.get("/{filename}.html")
    async def serve_html(filename: str):
        file_path = _FRONTEND_DIR / f"{filename}.html"
        if file_path.exists():
            return FileResponse(str(file_path))
        raise HTTPException(status_code=404, detail="Page not found")

    @app.get("/config.js", include_in_schema=False)
    async def serve_config_js():
        api_base = os.getenv("VITE_API_URL", "")
        content = f"""
const CONFIG = {{
    API_BASE: "{api_base}",
    VERSION: "{settings.app_version}"
}};
console.log('[SentinelGrid] Fallback Configuration Loaded');
"""
        return HTMLResponse(content=content, media_type="application/javascript")
else:
    @app.get("/")
    def root():
        return {"status": "healthy", "service": settings.app_name, "version": settings.app_version}
    logger.warning(f"Frontend folder not found at {_FRONTEND_DIR}")

# ========================
# LOCAL RUN
# ========================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.reload,
        log_level=settings.log_level.lower()
    )
