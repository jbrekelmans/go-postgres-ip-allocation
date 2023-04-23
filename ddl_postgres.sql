DROP INDEX IF EXISTS ip_range_allocated_to;
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
	allocated_to TEXT CHECK (allocated_to IS NULL OR length(allocated_to) > 0),
	PRIMARY KEY (pool_id, c)
);

CREATE UNIQUE INDEX IF NOT EXISTS ip_range_allocated_to ON ip_range (
	pool_id, allocated_to
) WHERE allocated_to IS NOT NULL;

CREATE INDEX IF NOT EXISTS ip_range_free ON ip_range (
	pool_id, masklen(c)
) WHERE allocated_to IS NULL;
