./build/release/duckdb enc_wal.db -key "asdf"
PRAGMA disable_checkpoint_on_shutdown;
PRAGMA wal_autocheckpoint='1TB';
CREATE TABLE test AS SELECT -i a, -i b FROM range(100000) tbl(i);
INSERT INTO test VALUES (11, 22), (NULL, 22), (12, 21);
UPDATE test SET b=b+1 WHERE a=11;
SELECT a, b FROM test WHERE a>0 OR a IS NULL ORDER BY a;
UPDATE test SET b=b+1 WHERE a=11;
UPDATE test SET b=NULL WHERE a=11;
SELECT a, b FROM test WHERE a>0 OR a IS NULL ORDER BY a;
SELECT a, b FROM test WHERE a>0 OR a IS NULL ORDER BY a;
`
