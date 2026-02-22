# api.py
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import shutil
import uuid
import os
import time
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

    try:
        # Analyze (static + dynamic)
        result = analyze_file(file_path)
        
        # Wait a bit for Docker to release file handles
        time.sleep(2)
        
        # Try to remove file with retry logic
        max_retries = 5
        for attempt in range(max_retries):
            try:
                os.remove(file_path)
                print(f"✅ Successfully deleted: {file_path}")
                break
            except PermissionError as e:
                if attempt < max_retries - 1:
                    print(f"⏳ Retry {attempt + 1}/{max_retries}: File still in use, waiting...")
                    time.sleep(2)
                else:
                    print(f"⚠️ Could not delete file after {max_retries} attempts: {e}")
                    # File will remain but analysis completed successfully
        
        return result
        
    except Exception as e:
        # If analysis fails, still try to clean up
        try:
            time.sleep(2)
            os.remove(file_path)
        except:
            pass
        raise e