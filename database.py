from sqlalchemy import create_engine
engine = create_engine('sqlite:///example.db')
 
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String
Base = declarative_base()
class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    name = Column(String)
    pas = Column(Integer)
