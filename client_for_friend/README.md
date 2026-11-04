# Client Setup for Demo Video (Laptop 2)

### 1. Prerequisites (Ubuntu / Linux / WSL)
```bash
sudo apt update && sudo apt install -y build-essential cmake libssl-dev
```

### 2. Build the Client
```bash
mkdir -p build && cd build
cmake ..
make -j$(nproc)
cd ..
```

### 3. Connect to Host Laptop (Replace <SERVER_IP> with your friend's IP, e.g. 10.81.8.215 or Hotspot IP)
```bash
# With strict Root CA TLS verification:
./build/client <SERVER_IP> 1312

# Or if running from build directory:
./client --ca ../certs/ca.crt <SERVER_IP> 1312

# Quick fallback (disables cert validation warning if needed):
./client -k <SERVER_IP> 1312
```

### 4. Demo Commands:
- `login bob password123`
- `ls`
- `upload demo_files/friend_report.txt`
- `ls`
- `download friend_report.txt`
- `logout`
- `exit`
