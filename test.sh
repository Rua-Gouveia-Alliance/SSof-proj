#!/bin/bash

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
        python src/js_analyser.py "$TEST" "$PATTERNS"
        python validate.py -o "$MYOUT" -t "$OUT"
    done
done
