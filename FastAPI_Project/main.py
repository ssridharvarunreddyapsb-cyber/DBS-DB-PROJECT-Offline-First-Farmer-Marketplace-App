from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from fastapi.responses import FileResponse
from pathlib import Path
from datetime import datetime, timezone, timedelta
import hashlib
import secrets
import random

app = FastAPI(title="Mandi Mitra API")
BASE_DIR = Path(__file__).resolve().parent

# ============================================================
# CORS - Allows your HTML frontend to communicate with FastAPI
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# MONGODB CONNECTION
# ============================================================

client = MongoClient("mongodb://localhost:27017/")

db = client["mandi_mitra"]

# New account records are stored in `users`, while `farmers` remains readable
# for compatibility with accounts created by the earlier version of the app.
farmers_collection = db["users"]
legacy_farmers_collection = db["farmers"]
products_collection = db["products"]
messages_collection = db["messages"]
sessions_collection = db["sessions"]
order_requests_collection = db["order_requests"]


# ============================================================
# DATA MODELS
# ============================================================

class Farmer(BaseModel):
    name: str
    email: str
    phone: str
    role: str
    city: str
    state: str
    address: str = ""
    pin: str | None = None
    captcha_token: str | None = None
    captcha_answer: str | None = None


class LoginRequest(BaseModel):
    phone: str
    pin: str
    captcha_token: str | None = None
    captcha_answer: str | None = None


class ResetPinRequest(BaseModel):
    phone: str
    pin: str
    captcha_token: str | None = None
    captcha_answer: str | None = None


class Product(BaseModel):
    farmer_id: str
    farmer_name: str
    name: str
    description: str = ""
    quantity: float
    unit: str
    price: float
    ready_by: str = ""
    status: str = "active"


class ChatMessage(BaseModel):
    sender_id: str
    sender_name: str
    recipient_id: str
    recipient_name: str
    body: str
    product_id: str = ""


class OrderRequest(BaseModel):
    buyer_id: str
    buyer_name: str
    farmer_id: str
    farmer_name: str
    farmer_phone: str = ""
    farmer_email: str = ""
    product_id: str
    product_name: str
    body: str


class OrderRequestReply(BaseModel):
    status: str
    reply: str


def object_id_or_400(value: str):
    from bson import ObjectId

    if not ObjectId.is_valid(value):
        raise HTTPException(status_code=400, detail="Invalid resource id")
    return ObjectId(value)


def serialize_user(user: dict):
    """Normalize older farmer records so the frontend can use every account."""
    # Credentials must never be returned to a browser or another API consumer.
    user.pop("pin", None)
    user.pop("pin_hash", None)
    user.pop("pin_salt", None)
    user["_id"] = str(user["_id"])
    user.setdefault("email", "")
    user.setdefault("phone", "")
    # Older records (for example role "Farmer") must match the lowercase values
    # the frontend compares against when choosing which dashboard to show.
    role = str(user.get("role") or "farmer").strip().lower()
    user["role"] = role if role in {"farmer", "buyer"} else "farmer"
    user.setdefault("city", user.get("village", user.get("district", "")))
    user.setdefault("state", "")
    return user


def order_user_snapshot(user: dict | None, user_id: str, fallback_name: str = ""):
    """Return public profile fields suitable for an order-request snapshot."""
    source = serialize_user(user.copy()) if user else {"_id": user_id, "name": fallback_name}
    fields = (
        "_id", "name", "email", "phone", "role", "address", "street",
        "village", "city", "district", "state", "postal_code", "zip",
    )
    return {field: source[field] for field in fields if source.get(field) is not None}


def find_user_by_id(user_id: str):
    from bson import ObjectId

    query_id = ObjectId(user_id) if ObjectId.is_valid(user_id) else user_id
    return farmers_collection.find_one({"_id": query_id}) or legacy_farmers_collection.find_one({"_id": query_id})


def valid_pin(pin: str | None) -> bool:
    return bool(pin and pin.isdigit() and 4 <= len(pin) <= 6)


def hash_pin(pin: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt.encode("utf-8"), 310_000).hex()


def set_pin(user: dict, pin: str):
    """Save a PIN in hashed form, updating whichever collection holds the user."""
    salt = secrets.token_hex(16)
    credentials = {"pin_salt": salt, "pin_hash": hash_pin(pin, salt)}
    farmers_collection.update_one({"_id": user["_id"]}, {"$set": credentials})
    legacy_farmers_collection.update_one({"_id": user["_id"]}, {"$set": credentials})
    user.update(credentials)


def find_user_by_phone(phone: str):
    return farmers_collection.find_one({"phone": phone}) or legacy_farmers_collection.find_one({"phone": phone})


captcha_store: dict[str, dict] = {}


def create_captcha():
    left = random.randint(2, 9)
    right = random.randint(2, 9)
    token = secrets.token_urlsafe(16)
    captcha_store[token] = {"answer": left + right, "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5)}
    return {"token": token, "question": f"What is {left} + {right}?"}


def validate_captcha(token: str | None, answer: str | None) -> bool:
    if not token or not answer:
        return False
    captcha = captcha_store.get(token)
    if captcha is None:
        return False
    if captcha["expires_at"] < datetime.now(timezone.utc):
        captcha_store.pop(token, None)
        return False
    ok = str(captcha["answer"]) == str(answer).strip()
    if ok:
        captcha_store.pop(token, None)
    return ok


def create_session(user: dict) -> str:
    token = secrets.token_urlsafe(32)
    sessions_collection.insert_one({
        "token": token,
        "user_id": user["_id"],
        "created_at": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(days=7),
    })
    return token


def get_authenticated_user(authorization: str | None):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")

    token = authorization.replace("Bearer ", "", 1).strip()
    session = sessions_collection.find_one({
        "token": token,
        "$or": [{"expires_at": {"$gt": datetime.now(timezone.utc)}}, {"expires_at": {"$exists": False}}],
    })
    if session is None:
        raise HTTPException(status_code=401, detail="Authentication required or session expired")

    user = farmers_collection.find_one({"_id": session["user_id"]}) or legacy_farmers_collection.find_one({"_id": session["user_id"]})
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required or session expired")
    return user


def seed_marketplace_if_empty():
    """Add any missing first-run Browse catalog items directly to MongoDB."""

    sellers = {
        "Lakshmi Farms": "a1b2c3d4e5f60718293a4b5c",
        "Sunrise Orchards": "b1c2d3e4f5a60718293a4b5c",
        "Green Valley Dairy": "c1d2e3f4a5b60718293a4b5c",
    }
    listings = [
        ("Lakshmi Farms", "Tomatoes", "Fresh red tomatoes, picked this morning.", 35, "kg", 32, "2026-09-16"),
        ("Lakshmi Farms", "Potatoes", "Clean, firm farm potatoes for everyday cooking.", 50, "kg", 28, "2026-09-16"),
        ("Lakshmi Farms", "Carrots", "Sweet orange carrots, naturally grown.", 20, "kg", 45, "2026-09-17"),
        ("Lakshmi Farms", "Spinach", "Fresh leafy spinach bunches.", 18, "bag", 25, "2026-09-16"),
        ("Sunrise Orchards", "Bananas", "Naturally ripened yellow bananas.", 12, "dozen", 55, "2026-09-16"),
        ("Sunrise Orchards", "Mangoes", "Seasonal sweet mangoes from the orchard.", 25, "kg", 90, "2026-09-18"),
        ("Sunrise Orchards", "Guavas", "Juicy, vitamin-rich guavas.", 16, "kg", 65, "2026-09-17"),
        ("Green Valley Dairy", "Fresh Cow Milk", "Pure chilled cow milk, delivered fresh daily.", 30, "bag", 60, "2026-09-16"),
        ("Green Valley Dairy", "Homemade Curd", "Thick, fresh-set curd with no additives.", 15, "kg", 85, "2026-09-16"),
        ("Green Valley Dairy", "Paneer", "Soft, fresh paneer made from full-cream milk.", 10, "kg", 380, "2026-09-17"),
        ("Green Valley Dairy", "Desi Ghee", "Traditional aromatic ghee, small-batch prepared.", 8, "kg", 720, "2026-09-17"),
    ]
    existing_names = {
        str(product.get("name", "")).strip().lower()
        for product in products_collection.find({}, {"name": 1})
    }
    starter_products = [
        {
            "farmer_id": sellers[seller], "farmer_name": seller, "name": name,
            "description": description, "quantity": quantity, "unit": unit,
            "price": price, "ready_by": ready_by, "status": "active",
        }
        for seller, name, description, quantity, unit, price, ready_by in listings
        if name.lower() not in existing_names
    ]
    if starter_products:
        products_collection.insert_many(starter_products)


@app.on_event("startup")
def initialise_database():
    client.admin.command("ping")
    seed_marketplace_if_empty()


# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():
    return FileResponse(BASE_DIR / "farmer-marketplace.html")


@app.get("/api/health")
def health_check():
    return {"message": "Mandi Mitra API is working!"}


# ============================================================
# CREATE FARMER
# ============================================================

@app.get("/auth/captcha")
def get_captcha():
    return create_captcha()


@app.post("/farmers")
def add_farmer(farmer: Farmer):

    if not valid_pin(farmer.pin):
        raise HTTPException(status_code=422, detail="PIN must contain 4 to 6 digits")
    if not validate_captcha(farmer.captcha_token, farmer.captcha_answer):
        raise HTTPException(status_code=403, detail="Captcha verification failed")

    farmer_data = farmer.model_dump(exclude={"pin", "captcha_token", "captcha_answer"})
    salt = secrets.token_hex(16)
    farmer_data["pin_salt"] = salt
    farmer_data["pin_hash"] = hash_pin(farmer.pin, salt)

    if farmers_collection.find_one({"phone": farmer.phone}) or legacy_farmers_collection.find_one({"phone": farmer.phone}):
        raise HTTPException(status_code=409, detail="An account with this phone already exists")

    try:
        result = farmers_collection.insert_one(farmer_data)
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail="An account with this phone already exists")

    created_user = {**farmer_data, "_id": result.inserted_id}
    token = create_session(created_user)
    return {
        "message": "Farmer added successfully",
        "id": str(result.inserted_id),
        "token": token,
        "user": serialize_user(created_user),
    }


# ============================================================
# GET ALL FARMERS
# ============================================================

@app.get("/farmers")
def get_farmers(authorization: str | None = Header(default=None, alias="Authorization")):
    get_authenticated_user(authorization)
    users = list(farmers_collection.find()) + list(legacy_farmers_collection.find())
    return [serialize_user(user) for user in users]


@app.get("/users")
def get_users(authorization: str | None = Header(default=None, alias="Authorization")):
    get_authenticated_user(authorization)
    return get_farmers(authorization)


@app.get("/farmers/by-phone/{phone}")
def get_farmer_by_phone(phone: str, authorization: str | None = Header(default=None, alias="Authorization")):
    get_authenticated_user(authorization)
    farmer = farmers_collection.find_one({"phone": phone}) or legacy_farmers_collection.find_one({"phone": phone})
    if farmer is None:
        raise HTTPException(status_code=404, detail="Farmer not found")

    return serialize_user(farmer)


@app.put("/farmers/{farmer_id}")
def update_farmer(farmer_id: str, farmer: Farmer, authorization: str | None = Header(default=None, alias="Authorization")):
    get_authenticated_user(authorization)
    user_id = object_id_or_400(farmer_id)
    # Never write a plain-text PIN: keep credentials out of the profile update
    # and only re-hash a PIN when one is explicitly supplied.
    update_data = farmer.model_dump(exclude={"pin"})
    result = farmers_collection.update_one({"_id": user_id}, {"$set": update_data})
    if result.matched_count == 0:
        result = legacy_farmers_collection.update_one({"_id": user_id}, {"$set": update_data})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Farmer not found")

    if farmer.pin:
        if not valid_pin(farmer.pin):
            raise HTTPException(status_code=422, detail="PIN must contain 4 to 6 digits")
        set_pin({"_id": user_id}, farmer.pin)

    return {"message": "Farmer updated successfully"}


# ============================================================
# CREATE PRODUCT
# ============================================================

@app.post("/products")
def add_product(product: Product, authorization: str | None = Header(default=None, alias="Authorization")):
    get_authenticated_user(authorization)

    product_data = product.model_dump()

    result = products_collection.insert_one(product_data)

    return {
        "message": "Product added successfully",
        "id": str(result.inserted_id)
    }


# ============================================================
# GET ALL PRODUCTS
# ============================================================

@app.get("/products")
def get_products(authorization: str | None = Header(default=None, alias="Authorization")):
    get_authenticated_user(authorization)

    products = list(products_collection.find())

    for product in products:
        product["_id"] = str(product["_id"])

    return products


@app.put("/products/{product_id}")
def update_product(product_id: str, product: Product, authorization: str | None = Header(default=None, alias="Authorization")):
    get_authenticated_user(authorization)
    result = products_collection.replace_one(
        {"_id": object_id_or_400(product_id)},
        product.model_dump()
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")

    return {"message": "Product updated successfully"}


# ============================================================
# DELETE PRODUCT
# ============================================================

@app.delete("/products/{product_id}")
def delete_product(product_id: str, authorization: str | None = Header(default=None, alias="Authorization")):
    get_authenticated_user(authorization)
    result = products_collection.delete_one(
        {"_id": object_id_or_400(product_id)}
    )

    if result.deleted_count == 0:
        return {
            "message": "Product not found"
        }

    return {
        "message": "Product deleted successfully"
    }


@app.post("/order-requests", status_code=201)
def create_order_request(request_data: OrderRequest, authorization: str | None = Header(default=None, alias="Authorization")):
    buyer = get_authenticated_user(authorization)
    buyer_id = str(buyer["_id"])
    if str(buyer.get("role", "")).lower() != "buyer":
        raise HTTPException(status_code=403, detail="Only buyers can create order requests")
    if not request_data.body.strip():
        raise HTTPException(status_code=422, detail="Order request cannot be empty")

    farmer = find_user_by_id(request_data.farmer_id)
    saved = request_data.model_dump()
    saved.update({
        "buyer_id": buyer_id,
        "buyer_name": buyer.get("name", request_data.buyer_name),
        "farmer_phone": (farmer or {}).get("phone", request_data.farmer_phone),
        "farmer_email": (farmer or {}).get("email", request_data.farmer_email),
        "buyer_user": order_user_snapshot(buyer, buyer_id, request_data.buyer_name),
        "farmer_user": order_user_snapshot(farmer, request_data.farmer_id, request_data.farmer_name),
        "body": request_data.body.strip(),
        "status": "pending",
        "reply": "",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "replied_at": "",
    })
    result = order_requests_collection.insert_one(saved)
    return {"message": "Order request sent", "id": str(result.inserted_id)}


@app.get("/order-requests/{user_id}")
def get_order_requests(user_id: str, authorization: str | None = Header(default=None, alias="Authorization")):
    user = get_authenticated_user(authorization)
    if str(user["_id"]) != user_id:
        raise HTTPException(status_code=403, detail="You can only view your own order requests")
    requests = list(order_requests_collection.find({"$or": [{"buyer_id": user_id}, {"farmer_id": user_id}]}).sort("created_at", -1))
    for request in requests:
        request["_id"] = str(request["_id"])
        request.setdefault("buyer_user", order_user_snapshot(find_user_by_id(request.get("buyer_id", "")), request.get("buyer_id", ""), request.get("buyer_name", "")))
        request.setdefault("farmer_user", order_user_snapshot(find_user_by_id(request.get("farmer_id", "")), request.get("farmer_id", ""), request.get("farmer_name", "")))
    return requests


@app.put("/order-requests/{request_id}")
def update_order_request(request_id: str, update: OrderRequestReply, authorization: str | None = Header(default=None, alias="Authorization")):
    user = get_authenticated_user(authorization)
    if update.status not in {"accepted", "declined"} or not update.reply.strip():
        raise HTTPException(status_code=422, detail="Choose a status and enter a reply")
    request = order_requests_collection.find_one({"_id": object_id_or_400(request_id)})
    if request is None:
        raise HTTPException(status_code=404, detail="Order request not found")
    if str(user["_id"]) != request.get("farmer_id"):
        raise HTTPException(status_code=403, detail="Only the requested farmer can reply")
    if request.get("status") != "pending":
        raise HTTPException(status_code=409, detail="This order request has already been answered")

    reply = update.reply.strip()
    order_requests_collection.update_one({"_id": request["_id"]}, {"$set": {
        "status": update.status,
        "reply": reply,
        "replied_at": datetime.now(timezone.utc).isoformat(),
    }})
    if update.status == "accepted":
        messages_collection.insert_one({
            "sender_id": request["farmer_id"],
            "sender_name": request["farmer_name"],
            "recipient_id": request["buyer_id"],
            "recipient_name": request["buyer_name"],
            "body": reply,
            "product_id": request.get("product_id", ""),
            "order_request_id": request_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    return {
        "message": "Order request updated",
        "conversation_peer_id": request["buyer_id"] if update.status == "accepted" else "",
    }


@app.post("/auth/login")
def login(credentials: LoginRequest):
    user = find_user_by_phone(credentials.phone)
    if user is None or not valid_pin(credentials.pin):
        raise HTTPException(status_code=401, detail="Invalid phone number or PIN")
    if not validate_captcha(getattr(credentials, 'captcha_token', None), getattr(credentials, 'captcha_answer', None)):
        raise HTTPException(status_code=403, detail="Captcha verification failed")

    salt = user.get("pin_salt")
    saved_hash = user.get("pin_hash")

    # Accounts created before PIN hashing was introduced have no stored
    # credential, so their owner would be locked out. The first login with a
    # valid PIN re-saves it in hashed form, matching the local Node server.
    if not salt or not saved_hash:
        set_pin(user, credentials.pin)
        token = create_session(user)
        response = serialize_user(user)
        response["token"] = token
        return response

    if not secrets.compare_digest(hash_pin(credentials.pin, salt), saved_hash):
        raise HTTPException(status_code=401, detail="Invalid phone number or PIN")

    token = create_session(user)
    response = serialize_user(user)
    response["token"] = token
    return response


@app.post("/auth/reset-pin")
def reset_pin(credentials: ResetPinRequest):
    user = find_user_by_phone(credentials.phone)
    if user is None:
        raise HTTPException(status_code=404, detail="No account found for this phone number")
    if not valid_pin(credentials.pin):
        raise HTTPException(status_code=422, detail="PIN must contain 4 to 6 digits")
    if not validate_captcha(getattr(credentials, 'captcha_token', None), getattr(credentials, 'captcha_answer', None)):
        raise HTTPException(status_code=403, detail="Captcha verification failed")

    set_pin(user, credentials.pin)
    return {"message": "PIN reset successfully"}


# ============================================================
# CHAT MESSAGES
# ============================================================

@app.post("/messages")
def send_message(message: ChatMessage, authorization: str | None = Header(default=None, alias="Authorization")):
    get_authenticated_user(authorization)
    message_data = message.model_dump()
    message_data["body"] = message_data["body"].strip()
    if not message_data["body"]:
        raise HTTPException(status_code=422, detail="Message cannot be empty")

    message_data["created_at"] = datetime.now(timezone.utc).isoformat()
    result = messages_collection.insert_one(message_data)
    return {"message": "Message sent", "id": str(result.inserted_id)}


@app.get("/messages/{user_id}")
def get_messages(user_id: str, peer_id: str | None = None, authorization: str | None = Header(default=None, alias="Authorization")):
    get_authenticated_user(authorization)
    query = {"$or": [{"sender_id": user_id}, {"recipient_id": user_id}]}
    if peer_id:
        query = {
            "$or": [
                {"sender_id": user_id, "recipient_id": peer_id},
                {"sender_id": peer_id, "recipient_id": user_id},
            ]
        }

    messages = list(messages_collection.find(query).sort("created_at", 1))
    for message in messages:
        message["_id"] = str(message["_id"])
    return messages
