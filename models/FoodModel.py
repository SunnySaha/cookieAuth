from bson import ObjectId
from pydantic import BaseModel


class FoodModel(BaseModel):
    name: str
    price: float
    is_available: bool = True
    tax: float = None
    is_tax_apply: bool = False

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        schema_extra = {
            "like": {
                "name": "Chicken Curry",
                "Price": 15.50,
                "is_available": True,
                "tax": 2.50,
                "is_tax_apply": False
            }
        }


class UpdateFoodModel(BaseModel):
    name: str = None
    price: float = None
    is_available: bool = None
    tax: float = None
    is_tax_apply: bool = None

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        schema_extra = {
            "like": {
                "name": "Chicken Curry",
                "Price": 15.50,
                "is_available": True,
                "tax": 2.50,
                "is_tax_apply": False
            }
        }


