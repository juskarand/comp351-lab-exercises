from typing import Optional, Dict, List

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

app = FastAPI(title="Activity 4 CRUD API - LEGO Sets")


class LegoSetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    theme: str = Field(..., min_length=1, max_length=100)
    pieces: int = Field(..., ge=1, le=50_000)
    set_number: str = Field(..., min_length=1, max_length=30)

class LegoSet(LegoSetCreate):
    id: int

class LegoSetUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    theme: Optional[str] = Field(None, min_length=1, max_length=100)
    pieces: Optional[int] = Field(None, ge=1, le=50_000)
    set_number: Optional[str] = Field(None, min_length=1, max_length=30)


sets: Dict[int, LegoSet] = {}
next_id = 1

def to_dict(model: BaseModel, exclude_unset: bool = False) -> dict:
    """Works with both Pydantic v1 and v2."""
    if hasattr(model, "model_dump"): 
        return model.model_dump(exclude_unset=exclude_unset)
    return model.dict(exclude_unset=exclude_unset)     

def model_copy(model: BaseModel, update: dict) -> BaseModel:
    """Works with both Pydantic v1 and v2."""
    if hasattr(model, "model_copy"):  
        return model.model_copy(update=update)
    return model.copy(update=update)                    


@app.get("/sets/", response_model=List[LegoSet])
def list_sets():
    return list(sets.values())


@app.post("/sets/", response_model=LegoSet, status_code=status.HTTP_201_CREATED)
def create_set(lego_set: LegoSetCreate):
    global next_id
    new_set = LegoSet(id=next_id, **to_dict(lego_set))
    sets[next_id] = new_set
    next_id += 1
    return new_set


@app.get("/sets/{set_id}", response_model=LegoSet)
def read_set(set_id: int):
    if set_id not in sets:
        raise HTTPException(status_code=404, detail="LEGO set not found")
    return sets[set_id]


@app.put("/sets/{set_id}", response_model=LegoSet)
def update_set(set_id: int, patch: LegoSetUpdate):
    if set_id not in sets:
        raise HTTPException(status_code=404, detail="LEGO set not found")

    stored = sets[set_id]
    update_data = to_dict(patch, exclude_unset=True)
    updated = model_copy(stored, update_data)
    sets[set_id] = updated
    return updated


@app.delete("/sets/{set_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_set(set_id: int):
    if set_id not in sets:
        raise HTTPException(status_code=404, detail="LEGO set not found")
    del sets[set_id]
    return None
