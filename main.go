package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	// Register postgres driver
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/jbrekelmans/go-sql-ip-management/cidr"
	"github.com/jbrekelmans/go-sql-ip-management/storage"
	sqlStorage "github.com/jbrekelmans/go-sql-ip-management/storage/sql"
)

var errRecordDoesNotExist = errors.New("record does not exist")

func main() {
	if err := mainCore(); err != nil {
		log.Fatal().Err(err).Send()
	}
}

func mainCore() (err error) {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	ctx := context.Background()
	ctx, cancelFunc := signal.NotifyContext(ctx, os.Interrupt)
	defer cancelFunc()
	a := app{poolID: 1}
	return a.run(ctx)
}

type app struct {
	db     *sql.DB
	poolID int
	s      storage.Storage
}

func (a *app) allocateIPCIDRRange(ctx context.Context, prefixBits int, allocatedTo string) (c cidr.CIDR, err error) {
	defer measure()()
	record, err := a.findAllocated(ctx, allocatedTo)
	if err != nil {
		return
	}
	if record != nil {
		if record.C.PrefixBits != prefixBits {
			err = fmt.Errorf(`allocateIPCIDRRange for allocatedTo=%#v was previously called with prefixBits=%d but now got prefixBits=%d`,
				allocatedTo, record.C.PrefixBits, prefixBits)
			return
		}
		c = record.C
		return
	}
	tx, err := a.s.BeginTransaction(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
		ReadOnly:  false,
	})
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				log.Error().Err(rollbackErr).Msg("error rolling back tx")
			}
		} else {
			err = tx.Commit()
		}
	}()
	record, err = tx.FindSmallestFree(ctx, a.poolID, prefixBits)
	if err != nil {
		return
	}
	if record == nil {
		err = errors.New("no free IP address range")
		return
	}
	if record.C.PrefixBits > prefixBits {
		err = errors.New("bug in code: FindSmallestFree returned record with a range of IP addresses that is smaller than the requested " +
			"minimal size")
		return
	}
	recordOldPrefixBits := record.C.PrefixBits
	var newRecords []storage.Record
	for record.C.PrefixBits < prefixBits {
		// Split the range of IP addresses into two.

		// Add a new record for the upper half.
		newRecords = append(newRecords, storage.Record{
			C:      record.C.Split(),
			PoolID: a.poolID,
		})

		// Update record to be the lower half.
		record.C.PrefixBits++
	}
	record.AllocatedTo = allocatedTo
	if recordOldPrefixBits != record.C.PrefixBits {
		recordOldC := record.C
		recordOldC.PrefixBits = recordOldPrefixBits
		err = tx.Delete(ctx, record.PoolID, recordOldC)
		if err != nil {
			return
		}
		newRecords = append(newRecords, *record)
	} else {
		err = tx.Update(ctx, *record)
		if err != nil {
			return
		}
	}
	err = tx.InsertMany(ctx, newRecords)
	if err != nil {
		return
	}
	c = record.C
	return
}

func (a *app) findAllocated(ctx context.Context, allocatedTo string) (record *storage.Record, err error) {
	tx, err := a.s.BeginTransaction(ctx, &sql.TxOptions{
		ReadOnly:  true,
		Isolation: sql.LevelReadUncommitted,
	})
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				log.Error().Err(rollbackErr).Msg("error rolling back tx")
			}
		} else {
			err = tx.Commit()
		}
	}()
	record, err = tx.FindAllocated(ctx, a.poolID, allocatedTo)
	return
}

func measure() func() {
	var funcName string
	if pc, _, _, ok := runtime.Caller(1); ok {
		if funcInfo := runtime.FuncForPC(pc); funcInfo != nil {
			funcName = funcInfo.Name()
		}
	}
	start := time.Now()
	return func() {
		elapsed := time.Since(start)
		log.Debug().Dur("t", elapsed).Msgf("%s", funcName)
	}
}

func (a *app) deallocateIPCIDRRange(ctx context.Context, allocatedTo string) (c cidr.CIDR, err error) {
	defer measure()()
	record, err := a.findAllocated(ctx, allocatedTo)
	if err != nil {
		return
	}
	if record == nil {
		err = errRecordDoesNotExist
		return
	}
	tx, err := a.s.BeginTransaction(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
		ReadOnly:  false,
	})
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				log.Error().Err(rollbackErr).Msg("error rolling back tx")
			}
		} else {
			err = tx.Commit()
		}
	}()
	c = record.C
	recordOldPrefixBits := record.C.PrefixBits
	record.AllocatedTo = ""
	for record.C.PrefixBits > 0 {
		var record2 *storage.Record
		record2, err = tx.Get(ctx, a.poolID, record.C.Other())
		if err != nil {
			return
		}
		if record2 == nil {
			// The CIDR that we can merge with has been subdivided.
			break
		}
		if record2.AllocatedTo != "" {
			// The CIDR that we can merge has been allocated to an object.
			break
		}
		if record.C.IsLower() {
			err = tx.Delete(ctx, record2.PoolID, record2.C)
		} else {
			recordOldC := record.C
			recordOldC.PrefixBits = recordOldPrefixBits
			err = tx.Delete(ctx, record.PoolID, recordOldC)
			record = record2
			recordOldPrefixBits = record.C.PrefixBits
		}
		if err != nil {
			return
		}
		record.C.PrefixBits--
	}
	recordOldC := record.C
	recordOldC.PrefixBits = recordOldPrefixBits
	err = tx.Delete(ctx, record.PoolID, recordOldC)
	if err != nil {
		return
	}
	records := [...]storage.Record{*record}
	err = tx.InsertMany(ctx, records[:])
	return
}

func (a *app) doDDLStatements(ctx context.Context) error {
	fileData, err := os.ReadFile("ddl_postgres.sql")
	if err != nil {
		return err
	}
	sqlStatements := strings.Split(string(fileData), ";")
	for _, sqlStatement := range sqlStatements {
		sqlStatement = strings.Trim(sqlStatement, "\n")
		if sqlStatement == "" {
			continue
		}
		log.Info().Str("q", sqlStatement).Msg("executing statement")
		_, err := a.db.ExecContext(ctx, sqlStatement)
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *app) dump(ctx context.Context) (err error) {
	rows, err := a.db.QueryContext(ctx, `SELECT c,allocated_to FROM public.ip_range WHERE pool_id=$1`, a.poolID)
	if err != nil {
		return
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			if err == nil {
				err = closeErr
			} else {
				log.Error().Err(closeErr).Msg("error closing rows")
			}
		}
	}()
	var records []storage.Record
	for rows.Next() {
		record := storage.Record{PoolID: a.poolID}
		var allocatedTo *string
		err = rows.Scan(&record.C, &allocatedTo)
		if err != nil {
			return
		}
		if allocatedTo != nil {
			record.AllocatedTo = *allocatedTo
		}
		records = append(records, record)
	}
	err = rows.Err()
	if err != nil {
		return
	}
	sort.Slice(records, func(i, j int) bool {
		record1 := records[i]
		record2 := records[j]
		return bytes.Compare(record1.C.IP, record2.C.IP) < 0
	})
	for _, record := range records {
		log.Info().Msgf("%d %s allocatedTo=%#v", record.PoolID, record.C.String(), record.AllocatedTo)
	}
	return
}

func (a *app) insertTestData(ctx context.Context, s string) (err error) {
	cidr, err := cidr.ParseCIDR(s)
	if err != nil {
		return
	}
	query := `INSERT INTO public.ip_pool(pool_id,pool_name) VALUES ($1,$2)`
	args := [...]any{a.poolID, "pool1"}
	log.Info().Str("q", query).Any("qv", args).Msg("executing statement")
	_, err = a.db.ExecContext(ctx, query, args[:]...)
	if err != nil {
		return
	}
	tx, err := a.s.BeginTransaction(ctx, nil)
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			rollbackErr := tx.Rollback()
			log.Printf("error rolling back tx: %v\n", rollbackErr)
		} else {
			err = tx.Commit()
		}
	}()
	err = tx.InsertMany(ctx, []storage.Record{{PoolID: a.poolID, C: cidr}})
	return
}

func (a *app) run(ctx context.Context) (err error) {
	// Open database.
	a.db, err = sql.Open("pgx/v5", "postgres://postgres:asdfasdf@localhost:5432/ipnet")
	if err != nil {
		return err
	}
	// Make sure database is closed.
	defer func() {
		if closeErr := a.db.Close(); closeErr != nil {
			if err == nil {
				err = closeErr
			} else {
				log.Error().Err(closeErr).Msg("error closing db")
			}
		}
	}()
	if err := a.doDDLStatements(ctx); err != nil {
		return err
	}
	a.s = sqlStorage.NewSQLStorage(a.db)
	if err := a.insertTestData(ctx, `0.0.0.0/16`); err != nil {
		return err
	}
	if err := a.dump(ctx); err != nil {
		return err
	}
	startTime := time.Now()
	const prefixBits = 26
	const parallelism = 10
	const allocationsPerWorker = 10
	var waitGroup sync.WaitGroup
	waitGroup.Add(parallelism)
	for i := 1; i <= parallelism; i++ {
		workerID := i
		go func() {
			defer waitGroup.Done()
			for i := 1; i <= allocationsPerWorker; {
				allocatedTo := fmt.Sprintf("worker%d_user%d", workerID, i)
				log := func(lvl zerolog.Level) *zerolog.Event {
					return log.WithLevel(lvl).Int("worker", workerID).Str("allocatedTo", allocatedTo)
				}
				var cidr cidr.CIDR
				cidr, err = a.allocateIPCIDRRange(ctx, prefixBits, allocatedTo)
				if err != nil {
					var pgErr *pgconn.PgError
					if errors.As(err, &pgErr) {
						log := func(lvl zerolog.Level) *zerolog.Event {
							return log(lvl).Str("severity", pgErr.Severity).Str("sqlstate", pgErr.Code)
						}
						// See https://www.postgresql.org/docs/current/errcodes-appendix.html
						switch pgErr.Code {
						case "40001", // Serialization Failure
							"23505": // Unique Violation
							log(zerolog.DebugLevel).Msgf("retrying on expected concurrency error: %s", pgErr.Message)
							continue
						}
						log(zerolog.ErrorLevel).Msgf("unexpected error: %s", pgErr.Message)
					} else {
						log(zerolog.ErrorLevel).Msgf("unexpected error: %v", err)
					}
					return
				}
				log(zerolog.InfoLevel).Msgf("allocated %v", cidr)
				i++
			}
		}()
	}
	waitGroup.Wait()
	for workerID := 1; workerID <= parallelism; workerID++ {
		for i := 1; i <= allocationsPerWorker; i++ {
			allocatedTo := fmt.Sprintf("worker%d_user%d", workerID, i)
			cidr, err := a.deallocateIPCIDRRange(ctx, allocatedTo)
			if err != nil {
				if !errors.Is(err, errRecordDoesNotExist) {
					return err
				}
				log.Debug().Str("allocatedTo", allocatedTo).Msgf("ignoring \"does not exist\" error")
				continue
			}
			log.Info().Str("allocatedTo", allocatedTo).Msgf("deallocated %v", cidr)
		}
	}
	log.Info().
		TimeDiff("t", time.Now(), startTime).
		Msgf("finished allocating and deallocating %d /%d CIDRs", parallelism*allocationsPerWorker, prefixBits)
	if err := a.dump(ctx); err != nil {
		return err
	}
	return nil
}
