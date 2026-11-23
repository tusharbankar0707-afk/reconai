"""ReconAI Flask entry point: pages, JSON API, rate limiting and error handling."""
import logging
import threading
import time
from collections import defaultdict, deque

from flask import Flask, Response, abort, jsonify, render_template, request

from config import Config
from database import repository as repo
from database.db import init_db
from modules import exporter, scan_engine
from modules.security import ValidationError, normalize_domain

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}
VALID_STATUSES = {"pending", "running", "completed", "failed"}


class RateLimiter:
    """Sliding-window limiter keyed by client address (in-process; use a shared store for multi-worker)."""

    def __init__(self, limit: int, window_seconds: int = 60):
        self.limit, self.window = limit, window_seconds
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True


def _err(message: str, status: int):
    return jsonify(error=message), status


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    init_db()
    repo.mark_orphaned_scans()
    limiter = RateLimiter(Config.RATE_LIMIT_PER_MINUTE)

    @app.before_request
    def rate_limit_scan_creation():
        if request.method == "POST" and request.path.startswith("/api/scans"):
            if not limiter.allow(request.remote_addr or "unknown"):
                return _err("Rate limit exceeded. Please wait a minute and retry.", 429)

    # ---------- Pages ----------
    @app.get("/")
    def index():
        return render_template("index.html", stats=repo.dashboard_stats(),
                               recent=repo.list_scans(limit=8))

    @app.get("/history")
    def history():
        return render_template("history.html")

    @app.get("/scans/<int:scan_id>")
    def scan_detail(scan_id: int):
        bundle = repo.get_bundle(scan_id)
        if not bundle:
            abort(404)
        return render_template("scan_detail.html", b=bundle)

    # ---------- JSON API ----------
    @app.post("/api/scans")
    def create_scan():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            payload = {}
        if payload.get("authorized") is not True:
            return _err("You must confirm you are authorized to assess this domain.", 400)
        try:
            domain = normalize_domain(payload.get("domain", ""))
        except ValidationError as exc:
            return _err(str(exc), 400)

        notes = str(payload.get("notes") or "")[:500] or None
        target_id = repo.upsert_target(domain, notes)
        scan_id = repo.create_scan(target_id)
        repo.log_action(scan_id, "queued", domain)
        scan_engine.submit(scan_id, domain)
        return jsonify(scan_id=scan_id, domain=domain, status="pending"), 202

    @app.get("/api/scans")
    def list_scans():
        severity = request.args.get("severity") or None
        status = request.args.get("status") or None
        if severity and severity not in VALID_SEVERITIES:
            return _err("Invalid severity filter.", 400)
        if status and status not in VALID_STATUSES:
            return _err("Invalid status filter.", 400)
        rows = repo.list_scans(q=request.args.get("q", "").strip()[:253] or None,
                               severity=severity, status=status,
                               limit=request.args.get("limit", 50, type=int))
        return jsonify(rows)

    @app.get("/api/scans/<int:scan_id>")
    def get_scan(scan_id: int):
        scan = repo.get_scan(scan_id)
        return jsonify(scan) if scan else _err("Scan not found.", 404)

    @app.get("/api/scans/<int:scan_id>/bundle")
    def get_bundle(scan_id: int):
        bundle = repo.get_bundle(scan_id)
        return jsonify(bundle) if bundle else _err("Scan not found.", 404)

    @app.delete("/api/scans/<int:scan_id>")
    def delete_scan(scan_id: int):
        if repo.delete_scan(scan_id):
            return jsonify(deleted=True)
        return _err("Scan not found.", 404)

    @app.post("/api/scans/<int:scan_id>/rescan")
    def rescan(scan_id: int):
        scan = repo.get_scan(scan_id)
        if not scan:
            return _err("Scan not found.", 404)
        if scan["status"] in ("pending", "running"):
            return _err("A scan for this target is already in progress.", 409)
        new_id = repo.create_scan(scan["target_id"])
        repo.log_action(new_id, "queued", f"rescan of #{scan_id}")
        scan_engine.submit(new_id, scan["domain"])
        return jsonify(scan_id=new_id), 202

    @app.get("/api/scans/<int:scan_id>/export")
    def export_scan(scan_id: int):
        bundle = repo.get_bundle(scan_id)
        if not bundle:
            return _err("Scan not found.", 404)
        fmt = request.args.get("format", "json")
        if fmt == "json":
            body, mime, ext = exporter.to_json(bundle), "application/json", "json"
        elif fmt in ("md", "markdown"):
            body, mime, ext = exporter.to_markdown(bundle), "text/markdown", "md"
        else:
            return _err("format must be 'json' or 'md'.", 400)
        filename = f"reconai-{bundle['scan']['domain']}-{scan_id}.{ext}"
        return Response(body, mimetype=mime,
                        headers={"Content-Disposition": f'attachment; filename="{filename}"'})

    @app.get("/api/stats")
    def stats():
        return jsonify(repo.dashboard_stats())

    # ---------- Errors ----------
    @app.errorhandler(404)
    def not_found(_):
        if request.path.startswith("/api/"):
            return _err("Not found.", 404)
        return "Page not found.", 404

    @app.errorhandler(500)
    def server_error(_):
        if request.path.startswith("/api/"):
            return _err("Internal server error.", 500)
        return "Internal server error.", 500

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
