from pydantic import BaseModel, Field, ConfigDict

class SetBase(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    theme: str = Field(min_length=2, max_length=50)
    pieces: int = Field(ge=1, le=20000)

class SetCreate(SetBase):
    pass

class SetUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=100)
    theme: str | None = Field(default=None, min_length=2, max_length=50)
    pieces: int | None = Field(default=None, ge=1, le=20000)

class SetOut(SetBase):
    id: int
    model_config = ConfigDict(from_attributes=True)
