"""Flask backend (app.py)."""
import os
from flask import Flask, jsonify, render_template, request
from src.predictor import Detector, MODEL_PATH

app = Flask(__name__)
_detector = None


def get_detector():
    global _detector
    if _detector is None:
        _detector = Detector()
    return _detector


@app.route("/")
def index():
    return render_template("index.html", error=None)


@app.route("/predict", methods=["POST"])
def predict():
    url = (request.form.get("url") or "").strip()
    if not url or len(url) > 2048:
        return render_template("index.html", error="Please enter a valid URL (max 2048 chars)."), 400
    if not os.path.exists(MODEL_PATH):
        return render_template("index.html", error="Model not trained yet. Run: python -m src.train"), 503
    return render_template("result.html", r=get_detector().predict(url))


@app.route("/api/predict", methods=["POST"])
def api_predict():
    url = ((request.get_json(silent=True) or {}).get("url") or "").strip()
    if not url or len(url) > 2048:
        return jsonify(error="url required (max 2048 chars)"), 400
    if not os.path.exists(MODEL_PATH):
        return jsonify(error="model not trained"), 503
    return jsonify(get_detector().predict(url))


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG") == "1")
