PRAGMA enable_temp_files_encryption;
PRAGMA memory_limit='8MB';
CREATE TEMPORARY TABLE tbl AS FROM range(10_000_000);
SELECT * from tbl;

