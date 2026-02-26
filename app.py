from __future__ import annotations

import re
from typing import Optional, Tuple, Union
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response
from flask.typing import ResponseReturnValue
import requests
from functools import wraps
import firebase_admin
from firebase_admin import credentials, firestore, auth
from firebase_admin.firestore import DocumentReference
import os

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "dev-secret-key")


# Initialize Firestore
if not firebase_admin._apps:
    service_account_path = os.getenv("FIREBASE_SERVICE_ACCOUNT", "serviceAccountKey.json")
    cred = credentials.Certificate(service_account_path)
    firebase_admin.initialize_app(cred)
db = firestore.client()

WEB_API_KEY = os.environ.get("FIREBASE_WEB_API_KEY")


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "uid" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. Grab the expected key from the environment
        expected_key = os.environ.get("SENSOR_API_KEY")

        # 2. Grab the provided key from the request headers
        key = request.headers.get("X-API-Key")

        # 3. Compare them
        if key != expected_key:
            return jsonify({"error": "Unauthorized"}), 401

        # 4. If they match, allow the route to execute normally
        return f(*args, **kwargs)
    return decorated_function


def get_current_user():
    """Return the currently logged-in username (or None).

    Uses session data set during `/login`. This keeps all login checks
    consistent in one place.
    """
    if not session.get("logged_in"):
        return None
    return session.get("uid")


def get_user_or_401():
    """Return the current API user or an Unauthorized response."""
    header = request.headers.get("Authorization")
    if not header or not header.startswith("Bearer "):
        return None, "Invalid token format"
    token = header.split(" ")[1]

    try:
        # Validates cryptographic signature
        decoded_token = auth.verify_id_token(token)
        return decoded_token["uid"], None
    except Exception as e:
        return None, f"Unauthorized: {str(e)}"


def get_profile_doc_ref(uid: str):
    """Get the Firestore document reference for a user's profile."""
    return db.collection("user_profiles").document(uid)


def get_profile_data(uid: str):
    """Fetch a user's profile from Firestore, returning an empty dict if missing."""
    doc = get_profile_doc_ref(uid).get()
    return doc.to_dict() if doc.exists else {}


def validate_profile_data(first_name: str, last_name: str, student_id: str):
    """Validate that required profile fields are present and well-formed."""
    if not first_name or not last_name or not student_id:
        return "All fields are required."
    return None


def normalize_profile_data(first_name: str, last_name: str, student_id: str):
    """Normalize profile field values (strip whitespace, stringify student_id)."""
    return {
        "first_name": first_name.strip().title() if first_name else "",
        "last_name": last_name.strip().title() if last_name else "",
        "student_id": str(student_id).strip() if student_id else ""
    }


def require_json_content_type():
    """Ensure the request is JSON; returns an error response tuple if not."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415
    return None


def set_profile(uid: str, profile_data: dict[str, str], *, merge: bool):
    """Persist profile data to Firestore.

    Args:
        uid: Profile owner.
        profile_data: Data to write.
        merge: When True, merges into existing document (partial update).
    """
    get_profile_doc_ref(uid).set(profile_data, merge=merge)


def validate_profile_update(data: dict[str, str]):
    errors = []
    allowed = {"first_name", "last_name", "student_id"}

    # 1. Whitelist Check - reject unknown fields
    if unknown := set(data.keys()) - allowed:
        errors.append(f"Unknown fields: {unknown}")

    # 2. Bounds Checking - enforce length limits
    if len(data.get("first_name", "")) > 50:
        errors.append("First Name must be 50 chars or less")

    if len(data.get("last_name", "")) > 50:
        errors.append("Last Name must be 50 chars or less")

    # 3. Pattern Validation - enforce format rules
    sid = data.get("student_id", "")
    if not re.match(r"^[A-Za-z0-9]{8,9}$", sid):
        errors.append("Invalid Student ID")

    return errors  # Return ALL errors


def validate_login_data(data: dict[str, str]):
    errors = []
    allowed = {"email", "password", "confirm_password"}

    # 1. Whitelist Check - reject unknown fields
    if unknown := set(data.keys()) - allowed:
        errors.append(f"Unknown fields: {unknown}")

    # 2. Bounds Checking - enforce length limits
    if len(data.get("email", "")) > 50:
        errors.append("email must be 50 chars or less")

    # 3. Pattern Validation - enforce format rules
    password = data.get("password", "")
    if not re.match(r"^[A-Za-z0-9]{7,50}$", password):
        errors.append("password invalid")

    return errors  # Return ALL errors


# --- Web Routes ---

@app.route("/")
@login_required
def home():
    """Home page. Redirects to login if no active session."""
    current_user = session["uid"]
    if current_user:
        profile_data = get_profile_data(current_user)
        name = profile_data.get("first_name")
        if name:
            return render_template("dashboard.html", username=name)
        return render_template("dashboard.html", username="")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """Login page."""
    if request.method == "GET":
        return render_template("login.html")

    # Get Firebase ID token from header
    header = request.headers.get("Authorization", "")
    if not header or not header.startswith("Bearer "):
        return render_template("login.html", error="Missing auth token")

    token = header.split(" ")[1]

    try:
        decoded_token = auth.verify_id_token(token)
        uid = decoded_token["uid"]

        # Create Flask session
        session["uid"] = uid

        return redirect(url_for("home"))

    except Exception:
        return render_template("login.html", error="Invalid or expired token")


@app.route("/logout")
@login_required
def logout():
    """Clear the session and return to login."""
    session.clear()
    return redirect(url_for("login"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """HTML form to create/update the current user's profile."""
    current_user = session["uid"]

    if request.method == "GET":
        profile_data = get_profile_data(current_user)
        return render_template("profile.html", profile=profile_data, error=None)

    first_name = request.form.get("first_name", "")
    last_name = request.form.get("last_name", "")
    student_id = request.form.get("student_id", "")

    profile_data = {"first_name": first_name, "last_name": last_name, "student_id": student_id}

    error = validate_profile_update(profile_data)
    if error:
        return render_template("profile.html", profile=profile_data, error=error)

    normalized = normalize_profile_data(first_name, last_name, student_id)
    set_profile(current_user, normalized, merge=True)
    return redirect(url_for("home"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")

    data = request.form.to_dict()

    email = request.form.get("email")
    password = request.form.get("password")
    confirm_password = request.form.get("confirm_password")

    # Validate input data
    error = validate_login_data(data)
    if error:
        return render_template("signup.html", error=error)

    # Validate passwords match
    if password != confirm_password:
        return render_template("signup.html", error="Passwords do not match")

    # TODO: Create user with Firebase Admin SDK
    user = auth.create_user(
        email=email,
        password=password
    )

    # TODO: Initialize profile in Firestore
    db.collection("user_profiles").document(user.uid).set({
        "email": email,
        "role": "user"
    })

    # TODO: Redirect to login on success
    return render_template("login.html")


# --- API Routes ---

@app.get("/api/profile")
def api_get_profile():
    """Return the current user's profile."""
    (user, error) = get_user_or_401()

    if error:
        return jsonify({"error": error}), 401

    profile_data = get_profile_data(user)

    return jsonify({"profile": profile_data}), 200


@app.post("/api/profile")
def api_create_profile():
    """Create/replace the current user's profile from a JSON body."""
    (user, error) = get_user_or_401()

    if error:
        return jsonify({"error": error}), 401

    content_error = require_json_content_type()
    if content_error:
        return content_error

    data = request.get_json(silent=True) or {}
    first_name = data.get("first_name", "")
    last_name = data.get("last_name", "")
    student_id = data.get("student_id", "")

    error = validate_profile_update(data)
    if error:
        return jsonify({"error": error}), 400

    normalized = normalize_profile_data(first_name, last_name, student_id)
    set_profile(user, normalized, merge=True)

    created_profile = get_profile_data(user)
    return jsonify({"message": "Profile saved successfully", "profile": created_profile}), 200


@app.put("/api/profile")
def api_update_profile():
    """Update the current user's profile from a JSON body."""
    (user, error) = get_user_or_401()

    if error:
        return jsonify({"error": error}), 401

    content_error = require_json_content_type()
    if content_error:
        return content_error

    data = request.get_json(silent=True) or {}
    if not data:
        return jsonify({"error": "Request body cannot be empty"}), 400

    error = validate_profile_update(data)
    if error:
        return jsonify({"error": error}), 400

    first_name = data.get("first_name")
    last_name = data.get("last_name")
    student_id = data.get("student_id")

    # Prepare the update data (only include provided fields)
    update_data = {}
    if first_name is not None:
        update_data["first_name"] = first_name.strip().title() if first_name else ""
    if last_name is not None:
        update_data["last_name"] = last_name.strip().title() if last_name else ""
    if student_id is not None:
        update_data["student_id"] = str(student_id).strip() if student_id else ""

    if not update_data:
        return jsonify({"error": "No updatable fields provided"}), 400

    # Merge update into existing document (or create if missing).
    set_profile(user, update_data, merge=True)

    updated_profile = get_profile_data(user)
    return jsonify({"message": "Profile updated successfully", "profile": updated_profile}), 200


@app.delete("/api/profile")
def api_delete_profile():
    """Delete the current user's profile."""
    (user, error) = get_user_or_401()

    if error:
        return jsonify({"error": error}), 401

    get_profile_doc_ref(user).delete()
    return jsonify({"message": "Profile deleted successfully"}), 200


@app.route("/api/signup", methods=["POST"])
def api_signup():
    data = request.json

    # 1. Create Identity in Auth
    user = auth.create_user(
    email=data.get("email"),
    password=data.get("password")
    )

    # 2. Initialize Profile in Firestore
    db.collection("user_profiles").document(user.uid).set({
    "email": data.get("email"),
    "role": "user"
    })

    return jsonify({"uid": user.uid}), 201


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.json
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={WEB_API_KEY}"
    payload = {"email": data["email"], "password": data["password"], "returnSecureToken": True}

    res = requests.post(url, json=payload)
    if res.status_code == 200:
        return jsonify({"token": res.json()["idToken"]}), 200
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/sensor_data", methods=["POST"])
@require_api_key
def api_sensor_data():
    data = request.json
    return jsonify({"message": "Test successful", "data": data}), 200


if __name__ == "__main__":
    app.run(debug=True, port=5000)
