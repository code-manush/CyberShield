from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.logging import setup_logging, logger
from app.database.session import engine, Base
from app.websocket.connection_manager import ws_manager
from app.monitoring.sniffer import sniffer_service
from app.ml.classifier import ml_classifier

# Import routers
from app.api.health import router as health_router
from app.api.monitoring import router as monitoring_router
from app.api.events import router as events_router
from app.api.prevention import router as prevention_router
from app.api.ml import router as ml_router
from app.api.auth import router as auth_router
from app.api.simulation import router as simulation_router

setup_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"[*] Starting {settings.PROJECT_NAME} v{settings.VERSION}...")
    # Initialize database tables
    Base.metadata.create_all(bind=engine)
    logger.info("[+] Database initialized successfully.")

    # Load ML model if present
    ml_classifier.load_model()

    yield

    logger.info("[*] Shutting down CyberShield...")
    sniffer_service.stop()
    logger.info("[+] Shutdown complete.")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Real-time Cyberattack Detection, Monitoring, and Prevention System",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(health_router)
app.include_router(monitoring_router)
app.include_router(events_router)
app.include_router(prevention_router)
app.include_router(ml_router)
app.include_router(auth_router)
app.include_router(simulation_router)


# WebSocket endpoint
@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        # Initial greeting with monitoring status
        await websocket.send_json({
            "type": "CONNECTION_ESTABLISHED",
            "data": {
                "service": settings.PROJECT_NAME,
                "status": sniffer_service.get_status()
            }
        })
        while True:
            # Keepalive / handle incoming messages from frontend
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception as e:
        logger.debug(f"[WEBSOCKET] Connection error: {e}")
        await ws_manager.disconnect(websocket)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
