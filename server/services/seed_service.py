from sqlalchemy.orm import Session
from models.models import Role, ClearanceLevel
from enums import RoleEnum, ClearanceLevelEnum


class SeedService:

    @staticmethod
    def seed_roles(db: Session):
        """Seed the roles table with predefined roles"""
        for role_enum in RoleEnum:
            existing = db.query(Role).filter(Role.label == role_enum.value).first()
            if not existing:
                role = Role(label=role_enum.value)
                db.add(role)
        db.commit()
        print("Roles seeded successfully")

    @staticmethod
    def seed_clearance_levels(db: Session):
        """Seed the clearance_levels table with predefined clearance levels"""
        for clearance_enum in ClearanceLevelEnum:
            existing = db.query(ClearanceLevel).filter(ClearanceLevel.label == clearance_enum.value).first()
            if not existing:
                clearance = ClearanceLevel(label=clearance_enum.value)
                db.add(clearance)
        db.commit()
        print("Clearance levels seeded successfully")

    @staticmethod
    def seed_all(db: Session):
        """Seed all required data"""
        SeedService.seed_roles(db)
        SeedService.seed_clearance_levels(db)
