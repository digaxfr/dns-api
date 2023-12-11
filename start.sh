#!/usr/bin/env bash

uvicorn main:app --reload --host "::0" --port 8000 # 2>stderr.log 1>stdout.log &
