import shutil
import typing
from json import dumps
from typing import Optional
import base64
from datetime import datetime, timedelta
from bson import ObjectId
from jose import JWTError, jwt
from passlib.context import CryptContext
import motor.motor_asyncio
from pydantic import BaseModel
import stripe
from fastapi import Depends, FastAPI, HTTPException, Body, WebSocket, WebSocketDisconnect, File, UploadFile
from fastapi.encoders import jsonable_encoder
from fastapi.security import OAuth2PasswordRequestForm, OAuth2
from fastapi.security.base import SecurityBase, SecurityBaseModel
from fastapi.security.utils import get_authorization_scheme_param
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.responses import HTMLResponse
from fastapi.openapi.utils import get_openapi
# from setuptools.build_meta import _file_with_extension
from starlette import status
from starlette.status import HTTP_403_FORBIDDEN
from starlette.responses import RedirectResponse, Response, JSONResponse
from starlette.requests import Request
from functools import lru_cache
# to get a string like this run:
# openssl rand -hex 32
from strawberry.types import Info

import helper.config
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from helper import config
from helper.helper import single_user, item_list, convert_dict, item_list2, convert_categories, categories_list, \
    lookup_items
from models.UserModel import TokenData, UserModel
import strawberry
from strawberry.fastapi import GraphQLRouter

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

client1 = motor.motor_asyncio.AsyncIOMotorClient("mongodb+srv://test1:1234@cluster0.vzlnp.mongodb.net/"
                                                 "myFirstDatabase?retryWrites=true&w=majority")

DATABASE_URL = "mongodb://localhost:27017/testing"

client2 = motor.motor_asyncio.AsyncIOMotorClient(DATABASE_URL)

db = client1.test_crud
db2 = client2.testing
db3 = client2.db_orders

crud_collection = db.crud
user_collection = db.user
orders = db3.order

menu_category_details = db2.menu_category_details
menu_category = db2.menu_category
category_item = db2.category_item
category_categories = db2.category_categories

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    }
}


class Token(BaseModel):
    access_token: str
    token_type: str


class User(BaseModel):
    username: str
    email: str = None
    full_name: str = None
    disabled: bool = None


class UserInDB(User):
    hashed_password: str


class OAuth2PasswordBearerCookie(OAuth2):
    def __init__(
            self,
            tokenUrl: str,
            scheme_name: str = None,
            scopes: dict = None,
            auto_error: bool = True,
    ):
        if not scopes:
            scopes = {}
        flows = OAuthFlowsModel(password={"tokenUrl": tokenUrl, "scopes": scopes})
        super().__init__(flows=flows, scheme_name=scheme_name, auto_error=auto_error)

    async def __call__(self, request: Request) -> Optional[str]:
        header_authorization: str = request.headers.get("Authorization")
        cookie_authorization: str = request.cookies.get("Authorization")

        header_scheme, header_param = get_authorization_scheme_param(
            header_authorization
        )
        cookie_scheme, cookie_param = get_authorization_scheme_param(
            cookie_authorization
        )

        if header_scheme.lower() == "bearer":
            authorization = True
            scheme = header_scheme
            param = header_param

        elif cookie_scheme.lower() == "bearer":
            authorization = True
            scheme = cookie_scheme
            param = cookie_param

        else:
            authorization = False

        if not authorization or scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN, detail="Not authenticated"
                )
            else:
                return None
        return param


class BasicAuth(SecurityBase):
    def __init__(self, scheme_name: str = None, auto_error: bool = True):
        self.scheme_name = scheme_name or self.__class__.__name__

        self.model = SecurityBaseModel(type="http")
        self.auto_error = auto_error

    async def __call__(self, request: Request) -> str | None:
        authorization: str = request.headers.get("Authorization")
        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "basic":
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN, detail="Not authenticated"
                )
            else:
                return None
        return param


basic_auth = BasicAuth(auto_error=False)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearerCookie(
    tokenUrl="/token",
    scopes={
        "me": "Read information about the current user.",
        "read_item": "Read items."
    },
)

# app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app = FastAPI()

templates = Jinja2Templates(directory="templates")

html = """
<!DOCTYPE html>
<html>
    <head>
        <title>Chat</title>
    </head>
    <body>
        <h1>WebSocket Chat as testing</h1>
        <form action="" onsubmit="sendMessage(event)">
            <input type="text" id="command" placeholder="command" autocomplete="off"/>
            <input type="text" id="package_id" placeholder="package Id" autocomplete="off"/>
            <button>Send</button>
        </form>
        <ul id='messages'>
        </ul>
        <script>
            var ws = new WebSocket("ws://localhost:8000/websocket");
            ws.onmessage = function(event) {
                var messages = document.getElementById('messages')
                var message = document.createElement('li')
                var content = document.createTextNode(event.data)
                message.appendChild(content)
                messages.appendChild(message)
            };
            function sendMessage(event) {
                var command = document.getElementById("command")
                var package_id = document.getElementById("package_id")
                str_concate = command.value + ' ' + package_id.value
                ws.send(str_concate)
                command.value = ''
                package_id.value = ''
                event.preventDefault()
            }
        </script>
    </body>
</html>
"""


@strawberry.type
class User:
    full_name: str


@strawberry.type
class Query:
    @strawberry.field
    def hello(self, name: str) -> str:
        user = get_user(fake_users_db, name)
        return user


schema = strawberry.Schema(query=Query)

graphql_app = GraphQLRouter(schema)
app.include_router(graphql_app, prefix="/graphql")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(*, data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=HTTP_403_FORBIDDEN, detail="Could not validate credentials"
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@lru_cache()
def get_settings():
    return config.Settings()


setting = get_settings()
app.mount("/static", StaticFiles(directory="static"), name="static")
stripe.api_key = setting.stripe_secret_key


@app.get('/websocket_connect_ui')
async def connect_socket_ui():
    return HTMLResponse(html)


@app.get('/payment-html', tags=['Payment View'])
async def confirm_payment(request: Request):
    return templates.TemplateResponse("payment.html", {"request": request})


@app.get('/success')
async def success_payment(request: Request):
    response = {
        'payment_intent': request.query_params['payment_intent'],
        'client_secret': request.query_params['payment_intent_client_secret'],
        'redirect_status': request.query_params['redirect_status'],
    }

    return templates.TemplateResponse("success.html", {"request": response})


@app.get('/cancel')
async def cancel_payment(request: Request):
    templates.get_template("cancel.html", {"request": request})


@app.post('/create-payment-session')
async def payment_session(request: Request):
    data = await request.json()
    create_intent = stripe.PaymentIntent.create(
        # success_url="http://localhost:8000/success?session_id={CHECKOUT_SESSION_ID}",
        # cancel_url="http://localhost:8000/cancel",
        # payment_method_types=["card"],
        # mode="payment",
        currency='usd',
        amount=data['amount'],

    )

    return {"paymentIntent": create_intent['client_secret']}


@app.get('/get_settings')
async def settings(setting: config.Settings = Depends(get_settings)):
    return {
        'app_name': setting.app_name,
        'app_key': setting.app_key,
        'app_version': setting.app_version
    }


@app.websocket('/websocket')
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    while True:
        data = await websocket.receive_text()
        value = data.split()
        response = {
            'command': str(value[0]),
            'package_id': str(value[1])
        }
        await websocket.send_json(response)


@app.get("/")
async def homepage():
    return "Welcome to the security test!"


@app.get("/localData")
async def local(versionid: str):
    items = await menu_category_details.find_one({'menuVersionId': versionid})
    categories = await menu_category.find_one({'menuVersionId': versionid})
    serilized_items = item_list2(items['items'])
    serilized_category = categories_list(categories['menuCategories'])
    if serilized_category and serilized_items:
        db2.drop_collection(category_categories)
        db2.drop_collection(category_item)
        encode1 = jsonable_encoder(serilized_items)
        input1 = await category_item.insert_many(encode1)
        encode = jsonable_encoder(serilized_category)
        input = await category_categories.insert_many(encode)
        response = {
            "msg": "split category & items related to this versionID",
            "status": 200
        }
    else:
        response = {
            "msg": "No item founds of this versionID",
            "status": 404
        }
    return response


@app.get("/getLookup")
async def lookup():
    pipeline = [{'$lookup': {'from': "category_item",
                             'localField': "category_id",
                             'foreignField': "category_id",
                             'as': "data"}
                 },
                {
                    '$sort': {'priority': -1}
                },
                {'$project':
                    {
                        '_id': 0,
                        'category': 1,
                        'restaurantid': 1,
                        'priority': 1,
                        'category_id': 1,
                        'data': 1,
                        "avg_price_of_items": {"$avg": "$data.price_takeaway"},
                        "sum_price_of_items": {"$sum": "$data.price_takeaway"},
                        "max_price_of_item": {"$max": "$data.price_takeaway"},
                        "min_price_of_item": {"$min": "$data.price_takeaway"},
                    }
                }
                ]
    aggregatess = category_categories.aggregate(pipeline)
    value = await aggregatess.to_list(length=None)
    serilized = lookup_items(value)
    response = {
        'msg': 'Get data Successfully',
        'status': 200,
        'data': serilized
    }

    return response


@app.post("/image-upload", tags=["Upload Image"])
async def upload_image(request: Request, file: UploadFile = File(...)):
    if request.method == "POST":
        image_url = str("media/" + file.filename)

        with open(image_url, "wb") as image:
            shutil.copyfileobj(file.file, image)

        response = {
            'file_name': file.filename,
            'file_type': file.content_type,
            'image_url': image_url
        }
        return response
    raise HTTPException(status_code=405, detail=f"this request should on POST method")


@app.post("/register", tags=["Sign Up"])
async def register(request: Request, user: UserModel = Body(...)):
    if request.method == "POST":
        user = jsonable_encoder(user)
        hashed_pass = get_password_hash(user['password'])
        user['password'] = hashed_pass
        inserted_user = await user_collection.insert_one(user)
        created_user = await user_collection.find_one({"_id": ObjectId(inserted_user.inserted_id)})
        get_serialized_user = single_user(created_user)
        response = {
            'user': get_serialized_user,
        }
        return JSONResponse(status_code=status.HTTP_201_CREATED, content=response)
    raise HTTPException(status_code=405, detail=f"this request should on POST method")


@app.post("/token", response_model=Token)
async def route_login_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/logout")
async def route_logout_and_remove_cookie():
    response = RedirectResponse(url="/")
    response.delete_cookie("Authorization", domain="localtest")
    return response


@app.get('/pub-key')
async def get_pub_stripe_key(request: Request, setting: config.Settings = Depends(get_settings)):
    response = {
        'msg': 'Stripe Publishable key',
        'pub_key': setting.stripe_pub_key
    }
    return response


@app.post('/payment')
async def stripe_payment(request: Request, amount: int):
    charge = stripe.Charge.create(
        amount=amount,
        currency="usd",
        description="Testing payment",
        source="tok_mastercard",
        idempotency_key='qUl8h3J1g7xxAs6Q',
        metadata={'order_id': '6735'}
    )
    # charge = charge.save()
    response = {
        'payload': charge,
    }
    return response


@app.get("/login_basic")
async def login_basic(auth: BasicAuth = Depends(basic_auth)):
    if not auth:
        response = Response(headers={"WWW-Authenticate": "Basic"}, status_code=401)
        return response

    try:
        decoded = base64.b64decode(auth).decode("ascii")
        username, _, password = decoded.partition(":")
        user = authenticate_user(fake_users_db, username, password)
        if not user:
            raise HTTPException(status_code=400, detail="Incorrect email or password")

        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": username}, expires_delta=access_token_expires
        )

        token = jsonable_encoder(access_token)

        response = RedirectResponse(url="/docs")
        response.set_cookie(
            "Authorization",
            value=f"Bearer {token}",
            domain="localhost",
            httponly=True,
            max_age=1800,
            expires=1800,
        )
        return response

    except:
        response = Response(headers={"WWW-Authenticate": "Basic"}, status_code=401)
        return response


@app.get("/openapi.json")
async def get_open_api_endpoint(current_user: User = Depends(get_current_active_user)):
    return JSONResponse(get_openapi(title="FastAPI", version=1, routes=app.routes))


@app.get("/docs")
async def get_documentation(current_user: User = Depends(get_current_active_user)):
    return get_swagger_ui_html(openapi_url="/openapi.json", title="docs")


@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@app.get("/users/me/items/")
async def read_own_items(current_user: User = Depends(get_current_active_user)):
    return [{"item_id": "Foo", "owner": current_user.username}]
