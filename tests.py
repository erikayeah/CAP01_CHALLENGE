from fastapi.testclient import TestClient
from main import app
import pytest

client = TestClient(app)


def test_register_new_user():
    response = client.post(
        "/register",
        json={
            "username": "newuser",
            "password": "newpass",
        },
    )
    assert response.status_code == 200, "No se devolvió un 200 al registrar usuario"


def test_register_existing_user():
    response = client.post(
        "/register",
        json={
            "username": "newuser",
            "password": "newpass",
        },
    )
    response = client.post(
        "/register",
        json={
            "username": "newuser",
            "password": "newpass",
        },
    )
    assert (
        response.status_code == 400
    ), "No se devolvió un 400 al intentar registrar usuario existente"


def test_login_existing_user():
    client.post(
        "/register",
        json={
            "username": "newuser",
            "password": "newpass",
        },
    )
    response = client.post(
        "/login",
        json={
            "username": "newuser",
            "password": "newpass",
        },
    )
    assert response.status_code == 200, "No se devolvió un 200"
    assert "access_token" in response.json(), "No se devolvió el access_token"


@pytest.fixture(scope="function")
def user_token():
    # Assuming this is a new user for each test
    username = "user_test"
    password = "test_password"
    client.post(
        "/register",
        json={
            "username": username,
            "password": password,
        },
    )
    response = client.post(
        "/login",
        json={
            "username": username,
            "password": password,
        },
    )
    return response.json()["access_token"]


def test_bubble_sort_authorized(user_token):
    # Registra un usuario y obtén el token

    token = user_token

    response = client.post(
        "/bubble-sort",
        params={"token": token},
        json={"numbers": [3, 2, 1]},
    )
    assert response.status_code == 200
    assert response.json() == {"numbers": [1, 2, 3]}


def test_bubble_sort_unauthorized(user_token):
    # Registra un usuario y obtén el token
    token = user_token
    token = token[:-1]

    response = client.post(
        "/bubble-sort",
        params={"token": token},
        json={"numbers": [3, 2, 1]},
    )
    assert response.status_code == 401


def test_bubble_sort_no_token(user_token):
    response = client.post(
        "/bubble-sort",
        json={"numbers": [3, 2, 1]},
    )
    assert response.status_code != 200


def test_filter_even(user_token):
    token = user_token
    response = client.post(
        "/filter-even",
        json={"numbers": [5, 3, 8, 6, 1, 9]},
        params={"token": token},
    )
    assert response.status_code == 200
    assert response.json() == {"even_numbers": [8, 6]}

    response = client.post(
        "/filter-even",
        json={"numbers": [1, 2, 3, 4, 5]},
        params={"token": token},
    )
    assert response.status_code == 200
    assert response.json() == {"even_numbers": [2, 4]}


def test_sum_elements(user_token):
    token = user_token
    response = client.post(
        "/sum-elements",
        json={"numbers": [5, 3, 8, 6, 1, 9]},
        params={"token": token},
    )
    assert response.status_code == 200
    assert response.json() == {"sum": 32}

    response = client.post(
        "/sum-elements",
        json={"numbers": [1, 2, 3, 4, 5]},
        params={"token": token},
    )
    assert response.status_code == 200
    assert response.json() == {"sum": 15}


def test_max_value(user_token):
    token = user_token
    response = client.post(
        "/max-value",
        json={
            "numbers": [5, 3, 8, 6, 1, 9],
        },
        params={"token": token},
    )
    assert response.status_code == 200
    assert response.json() == {"max": 9}

    response = client.post(
        "/max-value",
        json={
            "numbers": [1, 2, 3, 4, 5],
        },
        params={"token": token},
    )
    assert response.status_code == 200
    assert response.json() == {"max": 5}


def test_binary_search_found(user_token):
    token = user_token
    response = client.post(
        "/binary-search",
        params={"token": token},
        json={
            "numbers": [1, 2, 3, 4, 5],
            "target": 3,
        },
    )
    assert response.status_code == 200
    assert response.json() == {
        "found": True,
        "index": 2,
    }, "The target was not found or the wrong index was returned"


def test_binary_search_not_found(user_token):
    token = user_token
    response = client.post(
        "/binary-search",
        params={"token": token},
        json={
            "numbers": [1, 2, 3, 4, 5],
            "target": 6,
        },
    )
    assert response.status_code == 200
    assert response.json() == {
        "found": False,
        "index": -1,
    }, "The target was incorrectly found or the wrong index was returned"


def test_binary_search_unauthorized():
    response = client.post(
        "/binary-search",
        params={"token": "bad_token"},
        json={
            "numbers": [1, 2, 3, 4, 5],
            "target": 3,
        },
    )
    assert (
        response.status_code == 401
    ), "Unauthorized access did not return the expected HTTP 401 status code"
