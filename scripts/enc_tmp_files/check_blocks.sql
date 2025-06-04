PRAGMA memory_limit='1024KiB';
set max_temp_directory_size='256KiB';
CREATE OR REPLACE TABLE t2 AS SELECT random() FROM range(1000000);
select "tag"  from duckdb_memory();
select "tag"  from duckdb_memory() WHERE temporary_storage_bytes > 0;
select *  from duckdb_temporary_files();
