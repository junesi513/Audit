#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <scan_type> <bug_type>"
    exit 1
fi

export PATH=$HOME/.local/bin:$PATH
export GOOGLE_API_KEY=AIzaSyCWA58IOFNqypP0oENiOK5rvKApirD5P_w

SCAN_TYPE=$1
BUG_TYPE=$2
LANGUAGE=Java
MODEL=gemini-1.5-pro-latest
PROJECT=VUL4J

# For demo/test run
python3 ../repoaudit.py \
    --language $LANGUAGE \
    --model-name $MODEL \
    --project-path ../benchmark/${LANGUAGE}/${PROJECT}/${BUG_TYPE} \
    --bug-type $BUG_TYPE \
    --is-reachable \
    --temperature 0.0 \
    --scan-type $SCAN_TYPE \
    --call-depth 3 \
    --max-neural-workers 30
