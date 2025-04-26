import uvicorn
from fastapi import FastAPI
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from server.handlers import router
from server.auth import api_key_auth
import ssl

app = FastAPI(title="SecScan Server", docs_url=None)

# Security middlewares
app.add_middleware(HTTPSRedirectMiddleware)

# Include routes with authentication
app.include_router(router, dependencies=[api_key_auth])

if __name__ == "__main__":
    # SSL configuration
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(
        "ssl/server.crt",
        "ssl/server.key"
    )
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8443,
        ssl_certfile="ssl/server.crt",
        ssl_keyfile="ssl/server.key"
    )