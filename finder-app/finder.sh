#!/bin/sh

filesdir=$1
searchstr=$2

if [ $# -ne 2 ]; then
    echo "Invalid Number of arguments"
    exit 1
fi

if [ ! -d "$filesdir" ]; then
    echo "FILESDIR DOES NOT REPRESENT A DIRECTORY IN FILE SYSTEM"
    exit 1
fi

totalfiles=$(find $filesdir -type f | wc -l)
matchinglines=0

for i in $(find $filesdir -type f)
do
    if grep -q "$searchstr" "$i"; then
        matchinglines=$((matchinglines+1))
    fi
done

echo "The number of files are $totalfiles and the number of matching lines are $matchinglines"
