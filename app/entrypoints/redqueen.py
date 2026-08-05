from app.process_factory import create_restricted_application
from app.redqueen.router import router

app = create_restricted_application("redqueen", routers=[router])
