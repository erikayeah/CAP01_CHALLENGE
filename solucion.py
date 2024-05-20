from fastapi import FastAPI, HTTPException
from typing import List
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt


class Payload(BaseModel):
    numbers: List[int]


class BinarySearchPayload(BaseModel):
    numbers: List[int]
    target: int


# Fake db
fake_db = {"users": {}}

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def create_access_token(data: dict):
    to_encode = data.copy()
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_password_hash(password):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    print(plain_password, hashed_password)
    return pwd_context.verify(plain_password, hashed_password)


# Aplicacion
app = FastAPI()


class Credentials(BaseModel):
    username: str
    password: str


# Endpoint de registro, guarda clave encriptada
@app.post("/register")
def register(payload: Credentials):
    username = payload.username
    password = payload.password

    if username in fake_db["users"].keys():
        raise HTTPException(status_code=400, detail="User already exists")
    hashed_password = get_password_hash(password)
    fake_db["users"][username] = {"password": hashed_password}
    return {"message": "User registered successfully"}


# Endpoint de login, devuelve token
@app.post("/login")
def login(payload: Credentials):
    username = payload.username
    password = payload.password

    if username not in fake_db["users"]:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user = fake_db["users"][username]
    if not verify_password(password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token(data={"sub": username})
    return {"access_token": access_token}


# Función para verificar token
def get_current_user(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=401, detail="Invalid authentication credentials"
            )
        if username not in fake_db["users"].keys():
            raise HTTPException(
                status_code=401, detail="Invalid authentication credentials"
            )
    except:
        raise HTTPException(
            status_code=401, detail="Invalid authentication credentials"
        )


# Bubble Sort
@app.post("/bubble-sort")
def bubble_sort(payload: Payload, token: str):
    """
    Recibe una lista de números y devuelve la lista ordenada utilizando el algoritmo de Bubble Sort.
    """
    get_current_user(token)  # Verify token
    numbers = payload.numbers
    n = len(numbers)
    for i in range(n):
        for j in range(0, n - i - 1):
            if numbers[j] > numbers[j + 1]:
                numbers[j], numbers[j + 1] = numbers[j + 1], numbers[j]
    return {"numbers": numbers}


# Filtro de Pares
@app.post("/filter-even")
def filter_even(payload: Payload, token: str):
    """
    Recibe una lista de números y devuelve únicamente aquellos que son pares.
    """
    get_current_user(token)
    numbers = payload.numbers
    even_numbers = [number for number in numbers if number % 2 == 0]
    return {"even_numbers": even_numbers}


# Suma de Elementos
@app.post("/sum-elements")
def sum_elements(payload: Payload, token: str):
    """
    Recibe una lista de números y devuelve la suma de sus elementos.
    """
    get_current_user(token)
    numbers = payload.numbers
    return {"sum": sum(numbers)}


# Máximo Valor
@app.post("/max-value")
def max_value(payload: Payload, token: str):
    """
    Recibe una lista de números y devuelve el valor máximo.
    """
    get_current_user(token)
    numbers = payload.numbers
    return {"max": max(numbers)}


# Búsqueda Binaria
@app.post("/binary-search")
def binary_search(payload: BinarySearchPayload, token: str):
    """
    Recibe un número y una lista de números ordenados. Devuelve true y el índice si el número está en la lista, de lo contrario false y -1 como index.
    """
    get_current_user(token)

    numbers = payload.numbers
    target = payload.target

    left, right = 0, len(numbers) - 1
    while left <= right:
        mid = (left + right) // 2
        if numbers[mid] == target:
            return {"found": True, "index": mid}
        elif numbers[mid] < target:
            left = mid + 1
        else:
            right = mid - 1
    return {"found": False, "index": -1}
