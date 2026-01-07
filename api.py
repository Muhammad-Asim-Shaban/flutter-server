from fastapi import FastAPI, UploadFile, File
import shutil
import uuid
import os
from engine_core import analyze_file
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = FastAPI()

@app.post("/scan")
async def scan_file(file: UploadFile = File(...)):
    file_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_DIR, file_id + "_" + file.filename)

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    result = analyze_file(file_path)

    os.remove(file_path)

    return result
