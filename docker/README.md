# ATMG Sandbox Docker Images

## Quick Setup (Fixes Python import errors & pip timeout)

### 1. Build the Pre-configured Python Sandbox Image

```bash
cd docker
./build_sandbox_images.sh
```

This builds `atmg-python-sandbox:latest` with all dependencies pre-installed:
- bcrypt, flask, requests, sqlalchemy
- cryptography, passlib, pyjwt
- argon2-cffi, werkzeug

### 2. Verify Image Built

```bash
docker images | grep atmg-python-sandbox
```

Expected output:
```
atmg-python-sandbox   latest   xxxxx   X minutes ago   XXX MB
```

### 3. Run Your Pipeline

```bash
cd ..
python main.py
```

The sandbox will **automatically detect** and use the pre-built image!

---

## Benefits

### Before (using base python:3.12-slim):
- ❌ pip install on every run: **30-40 seconds**
- ❌ Import errors if network fails
- ❌ Timeout errors
- ❌ Total per-iteration: **4-5 minutes**

### After (using atmg-python-sandbox:latest):
- ✅ No pip install needed: **instant**
- ✅ All packages pre-installed
- ✅ No network required
- ✅ Total per-iteration: **2-3 minutes** (40% faster!)

---

## Troubleshooting

### If sandbox still uses base image:

Check if image exists:
```bash
docker images atmg-python-sandbox:latest
```

If missing, rebuild:
```bash
cd docker
docker build -t atmg-python-sandbox:latest -f Dockerfile.python-sandbox .
```

### To force rebuild:

```bash
docker rmi atmg-python-sandbox:latest
./build_sandbox_images.sh
```

---

## What Changed in sandbox.py

The code now:
1. Checks if `atmg-python-sandbox:latest` exists (lines 7-14)
2. Uses custom image if found, otherwise falls back to base image
3. Skips pip install when using custom image (lines 145-160)
4. Reduces timeout from 90s → 30s for pre-built image

**No manual changes needed** - it auto-detects the image!
