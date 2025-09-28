#!/usr/bin/env python3

from main import Base, engine, SessionLocal
from main import User, Note

print("Creating database tables...")
Base.metadata.create_all(bind=engine)
print("Tables created successfully!")

# Test database connection
try:
    db = SessionLocal()
    print("Database connection successful!")

    # Check if tables exist
    users = db.query(User).all()
    notes = db.query(Note).all()
    print(f"Found {len(users)} users and {len(notes)} notes in database")

    db.close()
except Exception as e:
    print(f"Database error: {e}")
    print("Make sure the database file can be created and accessed")
