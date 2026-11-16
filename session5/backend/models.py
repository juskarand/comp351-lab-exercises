from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer, String

Base = declarative_base()

class LegoSet(Base):
    __tablename__ = "sets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    theme = Column(String, nullable=False)
    pieces = Column(Integer, nullable=False)
