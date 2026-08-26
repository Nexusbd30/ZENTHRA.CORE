from app.ingestion.aresx_router import router as aresx_router
from app.ingestion.router import router as ingestion_router
from app.process_factory import create_restricted_application

app = create_restricted_application("ingestion", routers=[aresx_router, ingestion_router])
