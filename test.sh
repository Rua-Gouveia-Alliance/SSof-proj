#!/bin/bash

# Defining colors
RES=$(tput sgr0)
RED=$(tput setaf 1)$(tput bold)
GREEN=$(tput setaf 2)$(tput bold)
FAILED="${RED}failed$RES"
PASSED="${GREEN}passed$RES"

# Getting tests from the test directory
TESTDIRS=$(ls slices)

# Executing all tests
for DIR in $TESTDIRS; do
    TESTS=$(ls slices/"$DIR"/*.js)
    for TEST in $TESTS; do
        TESTNAME=${TEST%.js}
        PATTERNS="$TESTNAME".patterns.json
        OUT="$TESTNAME".output.json
        MYOUT=./output/$(basename "$TESTNAME").output.json
        python src/main.py "$TEST" "$PATTERNS"
        python validate.py -o "$MYOUT" -t "$OUT"
    done
done
