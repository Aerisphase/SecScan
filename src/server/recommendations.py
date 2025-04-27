from fastapi import APIRouter, Depends
from typing import List, Dict, Any
from src.ai import RecommenderSystem
from src.server.server import get_api_key

router = APIRouter()
recommender = RecommenderSystem()

class RecommendationResponse(BaseModel):
    vulnerability_type: str
    description: str
    recommendation: str
    severity: str
    confidence: float
    similarity_score: float

@router.get("/recommendations/{vulnerability_type}", response_model=List[RecommendationResponse])
async def get_recommendations(
    vulnerability_type: str,
    description: str,
    api_key: str = Depends(get_api_key)
):
    """Get recommendations for a specific vulnerability"""
    vulnerability_data = {
        'type': vulnerability_type,
        'description': description
    }
    recommendations = recommender.get_recommendations(vulnerability_data)
    return recommendations 