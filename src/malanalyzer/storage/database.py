"""Database Module - Manages data storage and retrieval"""

import os
import uuid
from typing import Optional, List, Dict
from datetime import datetime
from dataclasses import dataclass

try:
    from sqlalchemy import create_engine, Column, String, Integer, BigInteger, DateTime, JSON, Float, Boolean, ForeignKey, Text
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.orm import sessionmaker, relationship
    SQLALCHEMY_AVAILABLE = True
    Base = declarative_base()
except ImportError:
    SQLALCHEMY_AVAILABLE = False
    Base = None


if SQLALCHEMY_AVAILABLE:
    class Execution(Base):
        """Main execution table"""
        __tablename__ = 'executions'
        
        execution_id = Column(String(36), primary_key=True)
        file_hash = Column(String(64))
        file_name = Column(String(255))
        start_time = Column(DateTime)
        end_time = Column(DateTime)
        sandbox_id = Column(String(50))
        status = Column(String(20))
        
        # Relationships
        process_events = relationship("ProcessEvent", back_populates="execution")
        api_calls = relationship("APICall", back_populates="execution")
        file_operations = relationship("FileOperation", back_populates="execution")
        registry_operations = relationship("RegistryOperation", back_populates="execution")
        network_connections = relationship("NetworkConnection", back_populates="execution")


    class ProcessEvent(Base):
        """Process events table"""
        __tablename__ = 'process_events'
        
        event_id = Column(BigInteger, primary_key=True, autoincrement=True)
        execution_id = Column(String(36), ForeignKey('executions.execution_id'))
        timestamp = Column(DateTime)
        event_type = Column(String(50))
        process_id = Column(Integer)
        parent_process_id = Column(Integer)
        process_name = Column(String(255))
        command_line = Column(Text)
        user_name = Column(String(100))
        
        execution = relationship("Execution", back_populates="process_events")


    class APICall(Base):
        """API calls table"""
        __tablename__ = 'api_calls'
        
        call_id = Column(BigInteger, primary_key=True, autoincrement=True)
        execution_id = Column(String(36), ForeignKey('executions.execution_id'))
        timestamp = Column(DateTime)
        process_id = Column(Integer)
        thread_id = Column(Integer)
        api_name = Column(String(255))
        module_name = Column(String(255))
        parameters = Column(JSON)
        return_value = Column(String(100))
        
        execution = relationship("Execution", back_populates="api_calls")


    class FileOperation(Base):
        """File system operations table"""
        __tablename__ = 'file_operations'
        
        operation_id = Column(BigInteger, primary_key=True, autoincrement=True)
        execution_id = Column(String(36), ForeignKey('executions.execution_id'))
        timestamp = Column(DateTime)
        operation_type = Column(String(20))
        file_path = Column(Text)
        process_id = Column(Integer)
        status = Column(String(20))
        file_hash = Column(String(64))
        
        execution = relationship("Execution", back_populates="file_operations")


    class RegistryOperation(Base):
        """Registry operations table"""
        __tablename__ = 'registry_operations'
        
        operation_id = Column(BigInteger, primary_key=True, autoincrement=True)
        execution_id = Column(String(36), ForeignKey('executions.execution_id'))
        timestamp = Column(DateTime)
        operation_type = Column(String(20))
        key_path = Column(Text)
        value_name = Column(String(255))
        value_data = Column(Text)
        process_id = Column(Integer)
        
        execution = relationship("Execution", back_populates="registry_operations")


    class NetworkConnection(Base):
        """Network connections table"""
        __tablename__ = 'network_connections'
        
        connection_id = Column(BigInteger, primary_key=True, autoincrement=True)
        execution_id = Column(String(36), ForeignKey('executions.execution_id'))
        timestamp = Column(DateTime)
        protocol = Column(String(10))
        local_address = Column(String(50))
        local_port = Column(Integer)
        remote_address = Column(String(50))
        remote_port = Column(Integer)
        process_id = Column(Integer)
        bytes_sent = Column(BigInteger)
        bytes_received = Column(BigInteger)
        
        execution = relationship("Execution", back_populates="network_connections")


class Database:
    """Database manager"""
    
    def __init__(self, db_path: str = "./malanalyzer.db"):
        self.db_path = db_path
        self.engine = None
        self.Session = None
        
        if SQLALCHEMY_AVAILABLE:
            self._init_db()
        else:
            print("[Database] Warning: SQLAlchemy not available, using mock database")
    
    def _init_db(self):
        """Initialize database connection"""
        self.engine = create_engine(f'sqlite:///{self.db_path}')
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        print(f"[Database] Initialized database: {self.db_path}")
    
    def create_execution(self, file_hash: str, file_name: str, sandbox_id: str) -> str:
        """Create new execution record"""
        execution_id = str(uuid.uuid4())
        
        if not SQLALCHEMY_AVAILABLE:
            print(f"[Database] Mock: Created execution {execution_id}")
            return execution_id
        
        session = self.Session()
        try:
            execution = Execution(
                execution_id=execution_id,
                file_hash=file_hash,
                file_name=file_name,
                start_time=datetime.now(),
                sandbox_id=sandbox_id,
                status='running'
            )
            session.add(execution)
            session.commit()
            print(f"[Database] Created execution: {execution_id}")
        finally:
            session.close()
        
        return execution_id
    
    def update_execution_status(self, execution_id: str, status: str, end_time: Optional[datetime] = None):
        """Update execution status"""
        if not SQLALCHEMY_AVAILABLE:
            print(f"[Database] Mock: Updated execution {execution_id} status to {status}")
            return
        
        session = self.Session()
        try:
            execution = session.query(Execution).filter_by(execution_id=execution_id).first()
            if execution:
                execution.status = status
                if end_time:
                    execution.end_time = end_time
                session.commit()
                print(f"[Database] Updated execution {execution_id} status to {status}")
        finally:
            session.close()
    
    def add_process_event(self, execution_id: str, event_data: Dict):
        """Add process event"""
        if not SQLALCHEMY_AVAILABLE:
            return
        
        session = self.Session()
        try:
            event = ProcessEvent(
                execution_id=execution_id,
                timestamp=event_data.get('timestamp', datetime.now()),
                event_type=event_data['event_type'],
                process_id=event_data.get('process_id'),
                parent_process_id=event_data.get('parent_process_id'),
                process_name=event_data.get('process_name'),
                command_line=event_data.get('command_line'),
                user_name=event_data.get('user_name')
            )
            session.add(event)
            session.commit()
        finally:
            session.close()
    
    def get_execution(self, execution_id: str) -> Optional[Dict]:
        """Get execution details"""
        if not SQLALCHEMY_AVAILABLE:
            return None
        
        session = self.Session()
        try:
            execution = session.query(Execution).filter_by(execution_id=execution_id).first()
            if execution:
                return {
                    'execution_id': execution.execution_id,
                    'file_hash': execution.file_hash,
                    'file_name': execution.file_name,
                    'start_time': execution.start_time,
                    'end_time': execution.end_time,
                    'sandbox_id': execution.sandbox_id,
                    'status': execution.status
                }
        finally:
            session.close()
        
        return None
    
    def list_executions(self, limit: int = 100) -> List[Dict]:
        """List recent executions"""
        if not SQLALCHEMY_AVAILABLE:
            return []
        
        session = self.Session()
        try:
            executions = session.query(Execution).order_by(Execution.start_time.desc()).limit(limit).all()
            return [
                {
                    'execution_id': e.execution_id,
                    'file_hash': e.file_hash,
                    'file_name': e.file_name,
                    'start_time': e.start_time,
                    'status': e.status
                }
                for e in executions
            ]
        finally:
            session.close()


def init_database(db_path: str = "./malanalyzer.db") -> Database:
    """Initialize database"""
    return Database(db_path)
