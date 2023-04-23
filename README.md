# go-postgres-ip-allocation

This project contains Go code to manage IP CIDR range allocations transactionally using a SQL database.

Postgres is assumed and the connection string is hardcoded to `postgres://postgres:asdfasdf@localhost:5432/ipnet`.

## How to run

1. Create a database and/or update the hardcoded connection string.

2. Run the code:

    ```
    go run .
    ```

## How it works

The main functions in [main.go](main.go) are:

1. To allocate an IP CIDR range to an object identified as `allocatedTo`:

    ```go
    func (a *app) allocateIPCIDRRange(ctx context.Context, prefixBits int, allocatedTo string) (c cidr.CIDR, err error)
    ```

    This function will find the smallest big-enough free CIDR range, split it if needed, and allocate it to `allocatedTo` in a single transaction. 

2. To deallocate:

    ```go
    func (a *app) deallocateIPCIDRRange(ctx context.Context, allocatedTo string) (c cidr.CIDR, err error)
    ```

    This function will deallocate and aggressively merge free CIDR ranges, in a single transaction.

These algorithms minimize fragmentation, but allocation is subject to high contention so retrying on transaction serialization errors is needed to correctly allocate in case of concurrency. [main.go](main.go) shows how to retry on such errors for Postgres. Although `SQLState` errors are standard, other SQL providers may yield different errors.