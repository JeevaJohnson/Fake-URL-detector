# =========================
# IMPORTS
# =========================
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from detector import detect_url


# =========================
# CREATE APP
# =========================
app = FastAPI()


# =========================
# CORS (VERY IMPORTANT)
# =========================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # allow frontend access
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================
# ROOT CHECK (optional)
# =========================
@app.get("/")
def home():
    return {"message": "Phishing Detection API is running"}


# =========================
# MAIN API ENDPOINT
# =========================
@app.post("/predict")
def predict(data: dict):
    url = data.get("url")

    if not url:
        return {"error": "URL not provided"}

    result = detect_url(url)
    return result