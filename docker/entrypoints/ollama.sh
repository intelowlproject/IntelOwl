#!/bin/sh
# Start the Ollama server and ensure the default chat model is pulled.
# The model is configured via the OLLAMA_MODEL env var (set in env_file_app).

set -e

# Must stay in sync with the OLLAMA_MODEL defaults in intel_owl/settings/chatbot.py and
# docker/env_file_app_template; must be a model that supports Ollama tool calling.
DEFAULT_MODEL="qwen2.5:3b"
MODEL="${OLLAMA_MODEL:-$DEFAULT_MODEL}"

echo "[ollama] Starting server..."
ollama serve &
SERVER_PID=$!

echo "[ollama] Waiting for server to accept connections..."
until ollama list >/dev/null 2>&1; do
    sleep 1
done

echo "[ollama] Server ready. Checking for model '${MODEL}'..."
if ollama list | awk 'NR>1 {print $1}' | grep -Fxq "${MODEL}"; then
    echo "[ollama] Model '${MODEL}' already present, skipping pull."
else
    echo "[ollama] Pulling model '${MODEL}'..."
    PULL_OK=false
    for attempt in 1 2 3; do
        if ollama pull "${MODEL}"; then
            PULL_OK=true
            break
        fi
        echo "[ollama] Pull attempt ${attempt}/3 failed; retrying in 10s..."
        sleep 10
    done
    if [ "${PULL_OK}" != "true" ]; then
        echo "[ollama] WARN: pull of '${MODEL}' failed after 3 attempts. Server will continue running without it."
    fi
fi

echo "[ollama] Ready. PID=${SERVER_PID}"
wait "${SERVER_PID}"
