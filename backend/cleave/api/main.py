"""FastAPI skeleton. Real routes arrive with later phases; for now it just
proves the stack boots and can reach its dependencies."""
from fastapi import FastAPI

app = FastAPI(title="Cleave", version="0.1.0")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "cleave", "phase": 1}
