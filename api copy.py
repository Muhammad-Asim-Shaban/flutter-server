# api.py
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import shutil
import uuid
import os
from engine_core import analyze_file

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/scan")
async def scan_file(file: UploadFile = File(...)):
    """
    Scan file with static and dynamic analysis
    """
    file_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_DIR, file_id + "_" + file.filename)

    # Save uploaded file
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Analyze (static + dynamic)
    result = analyze_file(file_path)

    # Remove file after analysis
    os.remove(file_path)

    return result