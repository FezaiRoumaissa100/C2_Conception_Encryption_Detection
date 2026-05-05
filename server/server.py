from flask import Flask
from routes_c2 import c2_api
from routes_ui import ui_api

app = Flask(__name__)

# Register Blueprints
app.register_blueprint(c2_api)
app.register_blueprint(ui_api)

if __name__ == "__main__":
    print("[*] AES-256-GCM C2 Server started on port 5000")
    print("[*] Web Dashboard available at http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=True,ssl_context=('server.crt','server.key'))

