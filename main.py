from fastapi import FastAPI, HTTPException
from typing import List
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt

fake_db = {"users": {}}

app = FastAPI()


class Payload(BaseModel):
    numbers: List[int]


class BinarySearchPayload(BaseModel):
    numbers: List[int]
    target: int
