from fastapi import APIRouter, HTTPException
from app.simulation.attack_generator import attack_generator
from app.schemas.simulation import StartAttackRequest, AttackSimulationStatusResponse

router = APIRouter(prefix="/api/simulation", tags=["Simulation"])


@router.get("/status", response_model=AttackSimulationStatusResponse)
def get_simulation_status():
    """Retrieve current attack simulation status and live logs."""
    return attack_generator.get_status()


@router.post("/start", response_model=AttackSimulationStatusResponse)
def start_simulation(req: StartAttackRequest):
    """Trigger a real-time simulated cyberattack against the system."""
    try:
        status = attack_generator.start_attack(
            attack_type=req.attack_type,
            source_ip=req.source_ip,
            target_ip=req.target_ip,
            target_port=req.target_port,
            intensity=req.intensity,
            auto_enforce=req.auto_enforce
        )
        return status
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start simulation: {str(e)}")


@router.post("/stop")
def stop_simulation():
    """Abort any active attack simulation."""
    attack_generator.stop_attack()
    return {"status": "SUCCESS", "message": "Attack simulation stopped"}
