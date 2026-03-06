
import json
import queue
import threading
import time
import logging

from flask import Flask, render_template, request, Response, jsonify

from src.core.reconesis import ReconesisEngine

# ─────────────────────────────────────────────
# Flask App Setup
# ─────────────────────────────────────────────
app = Flask(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("reconesis.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("Dashboard")

# Global scan state
scan_active = False
event_queue: queue.Queue = queue.Queue()


def run_scan(target: str):
    """Runs the ReconesisEngine in a background thread and pushes events to the queue."""
    global scan_active
    scan_active = True

    def emit(event_type: str, data: dict):
        event_queue.put({"type": event_type, "data": data})

    try:
        engine = ReconesisEngine(event_callback=emit)
        engine.start_scan(target)
    except Exception as e:
        logger.error(f"Engine error: {e}", exc_info=True)
        emit("log", {"level": "error", "message": f"Fatal engine error: {e}"})
        emit("done", {"message": "Scan ended with errors."})
    finally:
        scan_active = False


# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/start", methods=["POST"])
def start_scan():
    global scan_active, event_queue

    if scan_active:
        return jsonify({"error": "A scan is already running."}), 409

    data = request.get_json()
    target = (data or {}).get("target", "").strip()
    if not target:
        return jsonify({"error": "No target specified."}), 400

    # Fresh queue for each scan
    event_queue = queue.Queue()
    thread = threading.Thread(target=run_scan, args=(target,), daemon=True)
    thread.start()
    logger.info(f"Scan started on target: {target}")
    return jsonify({"status": "started", "target": target})


@app.route("/stream")
def stream():
    """
    Server-Sent Events endpoint. The browser connects here and receives
    live scan events pushed by the engine's event_callback.
    """
    def generate():
        while True:
            try:
                event = event_queue.get(timeout=30)
                payload = json.dumps(event)
                yield f"data: {payload}\n\n"

                # Close stream when scan is done
                if event.get("type") == "done":
                    break
            except queue.Empty:
                # Send heartbeat to keep connection alive
                yield ": heartbeat\n\n"

    return Response(generate(), mimetype="text/event-stream",
                    headers={
                        "Cache-Control": "no-cache",
                        "X-Accel-Buffering": "no"
                    })


@app.route("/status")
def status():
    return jsonify({"scan_active": scan_active})


if __name__ == "__main__":
    print("=" * 55)
    print("  Reconesis Web Dashboard")
    print("  Open http://localhost:5000 in your browser")
    print("=" * 55)
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
