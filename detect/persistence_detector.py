import os
import hashlib 
import subprocess 

def check_modules():
    print("Checking loaded kernel modules...")
    try:
        result = subprocess.run(['lsmod'], stdout=subprocess.PIPE)
        modules = result.stdout.decode().splitlines()
        for module in modules:
            print(module)
    except Exception as e:
        print(f"Error checking modules: {e}")

def check_processes():
    print("Checking running processes...")
    try:
        result = subprocess.run(['ps', 'aux'], stdout=subprocess.PIPE)
        processes = result.stdout.decode().splitlines()
        for process in processes:
            print(process)
    except Exception as e:
        print(f"Error checking processes: {e}")

def check_file_integrity(file_path):
    print(f"Checking file integrity for {file_path}...")
    try:
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
            print(f"SHA-256 Hash: {file_hash}")
    except Exception as e:
        print(f"Error checking file integrity: {e}")

def main():
    check_modules()
    check_processes()
    check_file_integrity('/etc/passwd')

if __name__ == "__main__":
    main()
