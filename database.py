from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String

engine = create_engine('sqlite:///key_record.db')
Base = declarative_base()

class KeyRecord(Base):
    __tablename__ = 'key_records'
    id = Column(Integer, primary_key=True)
    original_key = Column(String, nullable=False)
    encrypted_key = Column(String, nullable=False)
    password = Column(String, nullable=False)

# # 创建表
# Base.metadata.create_all(engine)

# # 创建会话
Session = sessionmaker(bind=engine)
session = Session()
