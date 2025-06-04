./build/release/duckdb enc_wal.db -key "asdf";
SELECT a, b FROM test WHERE a>0 OR a IS NULL ORDER BY a;
