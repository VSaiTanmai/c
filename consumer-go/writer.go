package main

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// ── ClickHouseWriter — one native TCP connection, retry-capable ────────────

type ClickHouseWriter struct {
	id   int
	conn driver.Conn
	cfg  *Config
}

func NewClickHouseWriter(id int, cfg *Config) (*ClickHouseWriter, error) {
	w := &ClickHouseWriter{id: id, cfg: cfg}
	if err := w.connect(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *ClickHouseWriter) connect() error {
	addrs := []string{fmt.Sprintf("%s:%d", w.cfg.ClickHouseHost, w.cfg.ClickHousePort)}
	if w.cfg.ClickHouseAltHosts != "" {
		for _, h := range strings.Split(w.cfg.ClickHouseAltHosts, ",") {
			h = strings.TrimSpace(h)
			if h != "" {
				addrs = append(addrs, h)
			}
		}
	}

	for attempt := 1; attempt <= w.cfg.MaxRetries; attempt++ {
		conn, err := clickhouse.Open(&clickhouse.Options{
			Addr: addrs,
			Auth: clickhouse.Auth{
				Database: w.cfg.ClickHouseDB,
				Username: w.cfg.ClickHouseUser,
				Password: w.cfg.ClickHousePassword,
			},
			DialTimeout:    30 * time.Second,
			MaxOpenConns:   1,
			MaxIdleConns:   1,
			ConnMaxLifetime: 10 * time.Minute,
			Compression: &clickhouse.Compression{
				Method: clickhouse.CompressionLZ4,
			},
			Settings: clickhouse.Settings{
				"async_insert":                 1,
				"wait_for_async_insert":        0,
				"async_insert_busy_timeout_ms": 200,
				"async_insert_max_data_size":   104857600,
				"max_insert_threads":           4,
			},
		})
		if err != nil {
			slog.Warn("Writer connect failed", "writer", w.id, "attempt", attempt, "err", err)
			if attempt == w.cfg.MaxRetries {
				return fmt.Errorf("writer-%d: all %d connection attempts failed: %w", w.id, w.cfg.MaxRetries, err)
			}
			sleep := time.Duration(1<<uint(attempt)) * time.Second
			if sleep > 30*time.Second {
				sleep = 30 * time.Second
			}
			time.Sleep(sleep)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err = conn.Ping(ctx)
		cancel()
		if err != nil {
			slog.Warn("Writer ping failed", "writer", w.id, "attempt", attempt, "err", err)
			conn.Close()
			if attempt == w.cfg.MaxRetries {
				return fmt.Errorf("writer-%d: ping failed after %d attempts: %w", w.id, w.cfg.MaxRetries, err)
			}
			sleep := time.Duration(1<<uint(attempt)) * time.Second
			if sleep > 30*time.Second {
				sleep = 30 * time.Second
			}
			time.Sleep(sleep)
			continue
		}
		w.conn = conn
		slog.Info("Writer connected to ClickHouse", "writer", w.id, "addrs", addrs, "attempt", attempt)
		return nil
	}
	return fmt.Errorf("writer-%d: unreachable", w.id)
}

// Insert sends columnar data as a batch. Returns rows inserted.
func (w *ClickHouseWriter) Insert(ctx context.Context, table string, columns []string, rows [][]any) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}
	rowCount := len(rows)
	colStr := strings.Join(columns, ", ")
	query := fmt.Sprintf("INSERT INTO %s (%s)", table, colStr)

	for attempt := 1; attempt <= w.cfg.MaxRetries; attempt++ {
		batch, err := w.conn.PrepareBatch(ctx, query)
		if err != nil {
			slog.Warn("PrepareBatch failed", "writer", w.id, "table", table, "attempt", attempt, "err", err)
			if attempt == w.cfg.MaxRetries {
				return 0, fmt.Errorf("writer-%d: prepareBatch %s failed: %w", w.id, table, err)
			}
			w.reconnect()
			continue
		}
		for _, row := range rows {
			if err := batch.Append(row...); err != nil {
				slog.Warn("Batch.Append failed", "writer", w.id, "table", table, "attempt", attempt, "err", err)
				batch.Abort()
				if attempt == w.cfg.MaxRetries {
					return 0, fmt.Errorf("writer-%d: append %s failed: %w", w.id, table, err)
				}
				w.reconnect()
				break
			}
		}
		if err := batch.Send(); err != nil {
			slog.Warn("Batch.Send failed", "writer", w.id, "table", table, "attempt", attempt, "rows", rowCount, "err", err)
			if attempt == w.cfg.MaxRetries {
				return 0, fmt.Errorf("writer-%d: send %s (%d rows) failed: %w", w.id, table, rowCount, err)
			}
			// Exponential backoff with jitter — handles MinIO TooManyRequests (429)
			backoff := time.Duration(1<<uint(attempt)) * time.Second
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			jitter := time.Duration(rand.Int63n(int64(backoff / 2)))
			slog.Info("Backoff before retry", "writer", w.id, "table", table, "wait", backoff+jitter)
			time.Sleep(backoff + jitter)
			w.reconnect()
			continue
		}
		return rowCount, nil
	}
	return 0, fmt.Errorf("writer-%d: unreachable", w.id)
}

func (w *ClickHouseWriter) reconnect() {
	if w.conn != nil {
		w.conn.Close()
	}
	sleep := 2 * time.Second
	for i := 0; i < 5; i++ {
		if err := w.connect(); err == nil {
			return
		}
		time.Sleep(sleep)
		sleep *= 2
		if sleep > 30*time.Second {
			sleep = 30 * time.Second
		}
	}
}

func (w *ClickHouseWriter) Close() {
	if w.conn != nil {
		w.conn.Close()
	}
}

// ── WriterPool — one writer per flush goroutine ────────────────────────────

type WriterPool struct {
	ch chan *ClickHouseWriter
}

func NewWriterPool(size int, cfg *Config) (*WriterPool, error) {
	pool := &WriterPool{
		ch: make(chan *ClickHouseWriter, size),
	}
	for i := 0; i < size; i++ {
		w, err := NewClickHouseWriter(i, cfg)
		if err != nil {
			return nil, fmt.Errorf("writer pool init failed on writer %d: %w", i, err)
		}
		pool.ch <- w
	}
	slog.Info("ClickHouse writer pool ready", "size", size)
	return pool, nil
}

func (p *WriterPool) Acquire() *ClickHouseWriter {
	return <-p.ch
}

func (p *WriterPool) Release(w *ClickHouseWriter) {
	p.ch <- w
}

func (p *WriterPool) Close() {
	close(p.ch)
	for w := range p.ch {
		w.Close()
	}
}

// ── Columnar buffer — accumulates rows for a single table ──────────────────

type TableBuffer struct {
	mu   sync.Mutex
	rows [][]any
}

func NewTableBuffer() *TableBuffer {
	return &TableBuffer{
		rows: make([][]any, 0, 4096),
	}
}

func (tb *TableBuffer) Append(row []any) {
	tb.mu.Lock()
	tb.rows = append(tb.rows, row)
	tb.mu.Unlock()
}

// Snapshot returns current rows and resets the buffer (zero-alloc swap).
func (tb *TableBuffer) Snapshot() [][]any {
	tb.mu.Lock()
	snap := tb.rows
	tb.rows = make([][]any, 0, cap(snap))
	tb.mu.Unlock()
	return snap
}

func (tb *TableBuffer) Len() int {
	tb.mu.Lock()
	n := len(tb.rows)
	tb.mu.Unlock()
	return n
}

// ── FlushResult — outcome of a single table flush ──────────────────────────

type FlushResult struct {
	Table string
	Rows  int
	Err   error
}

// FlushAllParallel snapshots all non-empty buffers and flushes them concurrently.
// Returns total rows flushed and whether all flushes succeeded.
func FlushAllParallel(
	ctx context.Context,
	pool *WriterPool,
	buffers map[string]*TableBuffer,
	flushWorkers int,
) (totalRows int, allOK bool) {
	allOK = true
	type flushJob struct {
		table   string
		columns []string
		rows    [][]any
	}

	var jobs []flushJob
	for table, buf := range buffers {
		snap := buf.Snapshot()
		if len(snap) == 0 {
			continue
		}
		meta := tableMeta[table]
		if meta == nil {
			continue
		}
		jobs = append(jobs, flushJob{table: table, columns: meta.Columns, rows: snap})
	}

	if len(jobs) == 0 {
		return 0, true
	}

	results := make(chan FlushResult, len(jobs))
	sem := make(chan struct{}, flushWorkers)
	var wg sync.WaitGroup

	for _, job := range jobs {
		wg.Add(1)
		sem <- struct{}{} // limit concurrency
		go func(j flushJob) {
			defer wg.Done()
			defer func() { <-sem }()

			writer := pool.Acquire()
			n, err := writer.Insert(ctx, j.table, j.columns, j.rows)
			pool.Release(writer)

			results <- FlushResult{Table: j.table, Rows: n, Err: err}
		}(job)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for r := range results {
		if r.Err != nil {
			slog.Error("Flush failed", "table", r.Table, "rows", r.Rows, "err", r.Err)
			allOK = false
		} else {
			totalRows += r.Rows
			slog.Debug("Flushed", "table", r.Table, "rows", r.Rows)
		}
	}
	return totalRows, allOK
}
