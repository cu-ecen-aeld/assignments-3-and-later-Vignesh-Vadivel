#!/bin/bash
writefile=$1
writestr=$2

if [ $# -ne 2 ]; then
    echo "Invalid Number of Arguments"
    exit 1
fi

subpath=$(dirname ${writefile})
mkdir -p "$subpath"

echo "$writestr" > "$writefile"
