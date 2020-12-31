set -e; set -x
export ZOKRATES_HOME="${ZOKRATES_HOME:-$HOME/fork/ZoKrates/zokrates_stdlib/stdlib}"
ZOKRATES_BIN="${ZOKRATES_BIN:-$ZOKRATES_HOME/../../target/release/zokrates}"

rm -f out out.ztf proving.key verification.key abi.json log >/dev/null
${ZOKRATES_BIN} check --input legalage.zok > log 2>&1
${ZOKRATES_BIN} compile --input legalage.zok >> log 2>&1
${ZOKRATES_BIN} setup >> log 2>&1
${ZOKRATES_BIN} compute-witness -a 2001 18 2020 0 3 4 7999  >> log 2>&1
${ZOKRATES_BIN} --help
${ZOKRATES_BIN} generate-proof
${ZOKRATES_BIN} verify
${ZOKRATES_BIN} export-verifier
