from sqlalchemy import create_engine, Column, Integer, String, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import enum

"""SQLAlchemy models and DB session setup for SDN monitoring data.

This module defines attack history, users, and dropped-packet
tracking tables, then initializes a SQLite engine and shared session factory.
"""

Base = declarative_base()

class History(Base):
    """Detected attack event history used for mitigation decisions."""

    __tablename__ = 'history'
    id = Column(Integer, primary_key=True, autoincrement=True)
    Timestamp = Column(Float)
    Attack_type = Column(String(50))
    Attacker = Column(String(50))
    Victim = Column(String(50))
    Port = Column(String(50))
    Action = Column(String(50))
    Protocole = Column(String(50))


class User(Base):
    """Application user account table (includes default admin).

    Nothing to do with the IDS logic, only used by the web interface to authenticate who can view the dashboard.
    """

    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    Name = Column(String(150), unique=True)
    Email = Column(String(150), unique=True)
    Password = Column(String(150))


class Packets_dropped(Base):
    """Aggregated counter of dropped packets enforced by switch policy.
    
    Exists purely for the dashboard to show "X packets blocked".
    """

    __tablename__ = 'packets_dropped'
    id = Column(Integer, primary_key=True)
    Count = Column(Integer)

# Create the DB engine
db_path = '/mnt/mohamed/instance/sdn.db'
engine = create_engine(f'sqlite:///{db_path}')
Base.metadata.create_all(engine)

Session = sessionmaker(bind=engine)
session = Session()

def initialize_admin():
    """Create a default admin account if it does not exist.

    Used when running this module directly as a bootstrap helper.
    """
    admin = session.query(User).filter_by(Email='admin@gmail.com').first()
    if not admin:
        admin = User(Name='admin', Email='admin@gmail.com', Password='admin')
        session.add(admin)
        session.commit()
        print("Admin user added successfully!")
    else:
        print("Admin user already exists!")

if __name__ == "__main__":
    initialize_admin()
