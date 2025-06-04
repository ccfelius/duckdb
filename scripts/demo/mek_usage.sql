./build/release/duckdb -master_key "xxxx"
ATTACH 'master_key.db' as mkey;
use mkey;
CALL dbgen(sf=1);
