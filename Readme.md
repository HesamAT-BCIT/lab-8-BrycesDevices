[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/hK9g-dUi)
## **Overview**

In this lab, you are provided with a working Flask API and web application. However, **it is deeply insecure.** Currently, it relies on a hardcoded "dummy" user, uses basic session cookies for API routes, and lacks strict data validation.

Your task is to rip out the dummy logic and secure the API using Firebase Authentication (JWTs), Device Identity (API Keys), and strict validation.

---

## **Project Structure**

```
├── app.py                      # Main Flask application (routes + API)
├── requirements.txt            # Python dependencies
├── serviceAccountKey.json      # Firebase service account credentials
├── .env                        # Environment variables (create this)
└── templates/
    ├── login.html              # Login page (username/password form)
    ├── signup.html             # Signup page (email/password form)
    ├── dashboard.html          # User dashboard after login
    └── profile.html            # Profile creation/edit form
```

---

## **Existing Routes**

### Web Routes (HTML Pages)
| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Home - redirects to dashboard if logged in, otherwise to login |
| `/login` | GET, POST | Login page with dummy credentials |
| `/signup` | GET, POST | Signup page (you will implement this) |
| `/profile` | GET, POST | Create/update profile form |
| `/logout` | GET | Clear session and redirect to login |

### API Routes (JSON)
| Route | Method | Description |
|-------|--------|-------------|
| `/api/profile` | GET | Get current user's profile |
| `/api/profile` | POST | Create/replace profile (JSON) |
| `/api/profile` | PUT | Update profile fields (JSON) |
| `/api/profile` | DELETE | Delete current user's profile |

---

## **Pre-requisite: Firebase Setup**

To complete this lab, you need two credentials from your Firebase Console.

1. **Service Account Key (`serviceAccountKey.json`):** You should already have this from last week. This allows your Python server to talk to Firestore and verify JWTs using the Admin SDK.
2. **Web API Key:** *You need this new key to log users in via the REST API.*
    - Go to your Firebase Console.
    - Ensure **Authentication** is enabled and the "Email/Password" provider is turned on.
    - Go to **Project Settings** (gear icon in the top left) -> **General**.
    - Scroll down to "Your apps".
    - Click the `</>` (Web) icon to add a web app to your project.
    - Give it a nickname (e.g., "API Client") and click **Register app**.
    - Once registered, look for the **Web API Key** listed on the General settings page.
    - Store this inside your `.env` file as `FIREBASE_WEB_API_KEY=your-key-here`.

---

## **Task 1: The Firebase Auth Loop (Human Identity)**

The starter code uses `session.get("logged_in")` to verify users. You must replace this with a stateless, secure JWT implementation.

### **Step 1.1: Registration (Signup)**

The starter code includes a `signup.html` template in the `templates/` folder. You need to create the route handler and wire it up.

#### Web Route: `@app.route("/signup", methods=["GET", "POST"])`

Create a web route that renders the signup form on GET and processes the form on POST:

```python
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")

    email = request.form.get("email")
    password = request.form.get("password")
    confirm_password = request.form.get("confirm_password")

    # Validate passwords match
    if password != confirm_password:
        return render_template("signup.html", error="Passwords do not match")

    # TODO: Create user with Firebase Admin SDK
    # TODO: Initialize profile in Firestore
    # TODO: Redirect to login on success
```

#### JSON Route: `@app.route("/signup", methods=["POST"])`

For API clients, also create a JSON endpoint:

Creating a user requires a two-step synchronized process:

1. Use the Admin SDK to create the identity: `user = auth.create_user(email=email, password=password)`
2. Immediately initialize their profile in Firestore using the generated `uid` as the Document ID.

```python
from firebase_admin import auth

db.collection("profiles").document(user.uid).set({
    "email": email,
    "role": "user"
})
```

### **Step 1.2: Login (The Identity REST API)**

*Note: The Firebase Admin SDK in Python cannot log a user in with a password.* To generate a JWT, your server must send the user's credentials to the Google Identity Toolkit.

Create a new route: `@app.route("/login", methods=["POST"])`. Use the `requests` library to send the email, password, and your `FIREBASE_WEB_API_KEY`:

```python
import requests
import os

WEB_API_KEY = os.environ.get("FIREBASE_WEB_API_KEY")

@app.route("/login", methods=["POST"])
def api_login():
    data = request.json
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={WEB_API_KEY}"
    payload = {"email": data["email"], "password": data["password"], "returnSecureToken": True}

    res = requests.post(url, json=payload)
    if res.status_code == 200:
        return jsonify({"token": res.json()["idToken"]}), 200
    return jsonify({"error": "Invalid credentials"}), 401
```

### **Step 1.3: Token Verification (Replacing the Dummy User)**

Locate `get_user_or_401()` in the starter code. Rewrite it to look for a JWT instead of a session cookie:

1. Extract the `Authorization` header from `request.headers`.
2. Split the string to get the token (removing "Bearer ").
3. Use `auth.verify_id_token(token)` from the Firebase Admin SDK.
4. Return the decoded `uid`. If it fails, return a `401 Unauthorized` tuple.

*Test this in Postman by hitting `/login`, copying the `token`, and pasting it into the "Bearer Token" authorization tab for `GET /api/profile`.*

---

## **Task 2: Implementing Device Identity (API Keys)**

IoT hardware nodes cannot log in with passwords. We must use API Keys to authenticate them. To protect routes easily in Flask, we use **Decorators**.

### **What is a Decorator?**

A decorator (like `@app.route`) is simply a function that wraps *another* function. It runs some code *before* your route executes. If the request is bad, the decorator can intercept it and return an error before your route logic ever runs.

### **Instructions:**

1. **Generate a secure API key** and add it to your `.env` file.

   You can generate a secure random key using Python:
   ```python
   import secrets
   print(secrets.token_hex(32))
   ```

   Or using the command line:
   ```bash
   # On Linux/Mac
   openssl rand -hex 32

   # On Windows (PowerShell)
   [Convert]::ToHexString((1..32 | ForEach-Object { Get-Random -Maximum 256 })).ToLower()
   ```

   Add the generated key to your `.env` file:
   ```
   SENSOR_API_KEY=your-generated-key-here
   ```

2. Write a Flask Decorator called `@require_api_key`. Use the skeleton below:

```python
from functools import wraps
from flask import request, jsonify
import os

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. Grab the expected key from the environment
        expected_key = os.environ.get("SENSOR_API_KEY")

        # 2. Grab the provided key from the request headers
        # TODO: Get "X-API-Key" from request.headers

        # 3. Compare them
        # TODO: If they don't match, return jsonify({"error": "Unauthorized"}), 401

        # 4. If they match, allow the route to execute normally
        return f(*args, **kwargs)
    return decorated_function
```

3. Create a new dummy endpoint: `@app.route("/api/sensor_data", methods=["POST"])`. Apply your `@require_api_key` decorator to it (place it right *under* the `@app.route` decorator).
4. Test it using Postman by attempting to send data with and without the `X-API-Key` header.

---

## **Task 3: Robust Input Validation (Preventing Mass Assignment)**

Currently, `api_update_profile()` in the starter code handles updates, but we need to make it bulletproof.

**Instructions:** Modify the PUT route to implement these defensive concepts:

1. **Whitelist:** Reject any fields in the JSON payload other than `first_name`, `last_name`, and `student_id`.
2. **Bounds Checking:**
    - `first_name` and `last_name` must not exceed 50 characters.
    - `student_id` must be exactly 8 or 9 alphanumeric characters.
3. **Collect All Errors:** Instead of failing on the first bad field, check *all* of them. Append any errors to a list, and return a single `400 Bad Request` containing all the errors the user needs to fix at once.
