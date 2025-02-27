from pydantic import BaseModel
from typing import List

class Cpe(BaseModel):
    vulnerable: bool
    criteria: str
    matchCriteriaId: str

class CveDetails(BaseModel):
    cve_id: str
    description: str
    severity: str
    score: float
    vector_string: str
    access_vector: str
    access_complexity: str
    authentication: str
    confidentiality_impact: str
    integrity_impact: str
    availability_impact: str
    exploitability_score: float
    impact_score: float
    cpe: List[Cpe]