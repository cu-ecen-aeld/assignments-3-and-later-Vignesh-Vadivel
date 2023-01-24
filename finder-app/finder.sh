#!/bin/sh

filesdir=$1
searchstr=$2

#Checking for number of arguments.
if [ $# -ne 2 ]; then
    echo "Invalid Number of arguments"
    exit 1
fi

#Check if it is a valid directory or not.
if [ ! -d "$filesdir" ]; then
    echo "FILESDIR DOES NOT REPRESENT A DIRECTORY IN FILE SYSTEM"
    exit 1
fi

#Calculate total files present in the file system for present directory
totalfiles=$(find $filesdir -type f | wc -l)

#To store matching lines
matchinglines=0

#To check how many matching lines are present.
for i in $(find $filesdir -type f)
do
    if grep -q "$searchstr" "$i"; then
        matchinglines=$((matchinglines+1))
    fi
done

echo "The number of files are $totalfiles and the number of matching lines are $matchinglines"
