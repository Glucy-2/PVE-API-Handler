#!/usr/bin/bash
source .venv/bin/activate
gunicorn app:app -c gunicorn.conf.py
