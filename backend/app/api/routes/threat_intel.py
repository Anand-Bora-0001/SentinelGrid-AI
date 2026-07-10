from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, Any
from pydantic import BaseModel
from app.api.deps import get_current_user
from app.models import User
from app.ai.threat_rag import threat_rag_engine

router = APIRouter(prefix="/api/threat-intel", tags=["Threat Intelligence"])

class QuestionRequest(BaseModel):
    question: str

@router.post("/ask", response_model=Dict[str, Any])
def ask_threat_intel(request: QuestionRequest, current_user: User = Depends(get_current_user)):
    """
    Ask a question to the Threat Intelligence RAG Engine.
    """
    if not request.question:
        raise HTTPException(status_code=400, detail="Question cannot be empty")
        
    try:
        response = threat_rag_engine.ask(request.question)
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate threat explanation: {str(e)}")
