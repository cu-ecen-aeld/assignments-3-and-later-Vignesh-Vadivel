#!/bin/bash
writefile=$1
writestr=$2

#checking for valid arguments
if [ $# -ne 2 ]; then
    echo "Invalid Number of Arguments"
    exit 1
fi

#Get subpath from the given arguments
subpath=$(dirname ${writefile})

#Create all sub directories
mkdir -p "$subpath"

#Create and Write the contents to the file
echo "$writestr" > "$writefile"
