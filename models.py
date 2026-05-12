from sqlalchemy import Column, Integer, String, DateTime
from database import Base
import datetime

class LogEntry(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String)
    event_type = Column(String)
    severity = Column(String)
    description = Column(String)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)