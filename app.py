from flask import Flask, render_template, request
import pickle
import numpy as np

app = Flask(__name__)

# Load trained model
model = pickle.load(open("nids_model.pkl", "rb"))

# Store logs
logs = []

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():
    try:
        duration = int(request.form["duration"])
        protocol = request.form["protocol"]
        src_bytes = int(request.form["src_bytes"])
        dst_bytes = int(request.form["dst_bytes"])

        # Encode protocol manually
        protocol_map = {"ICMP": 0, "TCP": 1, "UDP": 2}
        protocol_encoded = protocol_map.get(protocol.upper(), 1)

        data = np.array([[duration, protocol_encoded, src_bytes, dst_bytes]])
        prediction = model.predict(data)[0]

        # Map numeric result to label if needed
        if prediction == 0 or prediction == 'Normal':
            label = "Normal"
        else:
            label = "Intrusion"

        logs.append({
            "duration": duration,
            "protocol": protocol,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "result": label
        })

        return render_template("result.html", result=label,
                               duration=duration, protocol=protocol,
                               src_bytes=src_bytes, dst_bytes=dst_bytes)
    except Exception as e:
        return f"Error: {e}"

@app.route("/dashboard")
def dashboard():
    total = len(logs)
    attacks = sum(1 for log in logs if log["result"] != "Normal")
    return render_template("dashboard.html", logs=logs, total=total, attacks=attacks)

if __name__ == "__main__":
    app.run(debug=True)
