#!/usr/bin/env python3
"""
Server Runner for CertGuard SSL Certificate Checker.
"""
import sys
import uvicorn

if __name__ == "__main__":
    host = "127.0.0.1"
    port = 8000
    print(f"\n========================================================")
    print(f"🔒 CertGuard - SSL Certificate Checker & Health Auditor")
    print(f"========================================================")
    print(f"🌐 Web UI Dashboard: http://{host}:{port}")
    print(f"📖 API Swagger Docs: http://{host}:{port}/docs")
    print(f"⚡ Press Ctrl+C to stop the server\n")
    
    uvicorn.run("app.main:app", host=host, port=port, reload=False)
