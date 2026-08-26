from app.ares.router import router
from app.process_factory import create_restricted_application

app = create_restricted_application("ares", routers=[router])
