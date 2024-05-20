from fastapi import FastAPI, HTTPException, Depends, Query
from typing import List, Optional
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt
import uvicorn

fake_db = {"users": {}}
SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"

app = FastAPI()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class Payload(BaseModel):
    numbers: List[int]


class BinarySearchPayload(BaseModel):
    numbers: List[int]
    target: int


class User(BaseModel):
    username: str
    password: str


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[int] = None):
    encoded_jwt = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(token: str = Query(...)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None or username not in fake_db["users"]:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        return username
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid credentials")


@app.post("/register")
async def register(user: User):
    if user.username in fake_db["users"]:
        raise HTTPException(status_code=400, detail="User already exists")
    hashed_password = get_password_hash(user.password)
    fake_db["users"][user.username] = hashed_password
    return {"message": "User registered successfully"}


@app.post("/login")
async def login(user: User):
    if user.username not in fake_db["users"] or not verify_password(user.password, fake_db["users"][user.username]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token}


@app.post("/bubble-sort")
async def bubble_sort(payload: Payload, username: str = Depends(get_current_user)):
    numbers = payload.numbers[:]
    n = len(numbers)
    for i in range(n):
        for j in range(0, n-i-1):
            if numbers[j] > numbers[j+1]:
                numbers[j], numbers[j+1] = numbers[j+1], numbers[j]
    return {"numbers": numbers}


@app.post("/filter-even")
async def filter_even(payload: Payload, username: str = Depends(get_current_user)):
    even_numbers = [num for num in payload.numbers if num % 2 == 0]
    return {"even_numbers": even_numbers}


@app.post("/sum-elements")
async def sum_elements(payload: Payload, username: str = Depends(get_current_user)):
    total_sum = sum(payload.numbers)
    return {"sum": total_sum}


@app.post("/max-value")
async def max_value(payload: Payload, username: str = Depends(get_current_user)):
    max_num = max(payload.numbers)
    return {"max": max_num}


@app.post("/binary-search")
async def binary_search(payload: BinarySearchPayload, username: str = Depends(get_current_user)):
    numbers = payload.numbers
    target = payload.target
    left, right = 0, len(numbers) - 1
    found = False
    index = -1
    while left <= right:
        mid = (left + right) // 2
        if numbers[mid] == target:
            found = True
            index = mid
            break
        elif numbers[mid] < target:
            left = mid + 1
        else:
            right = mid - 1
    return {"found": found, "index": index}


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
