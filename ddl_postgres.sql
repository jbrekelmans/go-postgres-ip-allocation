DROP INDEX IF EXISTS ip_range_request_id;
DROP INDEX IF EXISTS ip_range_free;
DROP TABLE IF EXISTS ip_range;
DROP TABLE IF EXISTS ip_pool;

CREATE TABLE IF NOT EXISTS ip_pool (
    pool_id SMALLINT PRIMARY KEY CHECK (pool_id > 0),
    pool_name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ip_range (
	pool_id SMALLINT NOT NULL REFERENCES ip_pool(pool_id),
	c CIDR NOT NULL,
	request_id TEXT CHECK (request_id IS NULL OR length(request_id) > 0),
	PRIMARY KEY (pool_id, c)
);

CREATE UNIQUE INDEX IF NOT EXISTS ip_range_request_id ON ip_range (
	pool_id, request_id
) WHERE request_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS ip_range_free ON ip_range (
	pool_id, masklen(c)
) WHERE request_id IS NULL;
