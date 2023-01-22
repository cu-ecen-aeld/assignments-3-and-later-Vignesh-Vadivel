#!/bin/bash
writefile=$1
writestr=$2

if [ $# -ne 2 ]; then
    echo "Invalid Number of Arguments"
    exit 1
fi

if [[ $writefile == *"/"* ]]; then
    subpath="${writefile%/*}/"
    echo "SUB_DIRECTORY"
    mkdir -p "$subpath"
fi

touch  "$writefile"
echo "$writestr" > "$writefile"
