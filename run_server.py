#!/usr/bin/env python3

"""
Server Runner for CertGuard SSL Certificate Checker.
"""

import os
import uvicorn


if __name__ == "__main__":
    # Local machine ke liye 8000,
    # Render/cloud deployment mein PORT environment variable use hoga.
    host = "0.0.0.0"
    port = int(os.environ.get("PORT", 8000))

    print("\n========================================================")
    print("🔒 CertGuard - SSL Certificate Checker & Health Auditor")
    print("========================================================")
    print(f"🌐 Web UI Dashboard: http://{host}:{port}")
    print(f"📖 API Swagger Docs: http://{host}:{port}/docs")
    print("⚡ Press Ctrl+C to stop the server\n")

    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=False
    )