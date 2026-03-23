package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/valyala/fastjson"
)

// ── Stats tracker ──────────────────────────────────────────────────────────

type Stats struct {
	mu          sync.Mutex
	counts      map[string]int64
	errors      int64
	parseErrors int64
	flushCount  int64
	flushRows   int64
	lastTotal   int64
	lastTime    time.Time
}

func NewStats() *Stats {
	return &Stats{
		counts:   make(map[string]int64),
		lastTime: time.Now(),
	}
}

func (s *Stats) RecordMessages(topic string, count int64) {
	s.mu.Lock()
	s.counts[topic] += count
	s.mu.Unlock()
}

func (s *Stats) RecordError(count int64) {
	s.mu.Lock()
	s.errors += count
	s.mu.Unlock()
}

func (s *Stats) RecordParseError(count int64) {
	s.mu.Lock()
	s.parseErrors += count
	s.mu.Unlock()
}

func (s *Stats) RecordFlush(rows int) {
	s.mu.Lock()
	s.flushCount++
	s.flushRows += int64(rows)
	s.mu.Unlock()
}

func (s *Stats) Report() {
	s.mu.Lock()
	defer s.mu.Unlock()

	var total int64
	for _, c := range s.counts {
		total += c
	}
	now := time.Now()
	elapsed := now.Sub(s.lastTime).Seconds()
	rate := float64(total-s.lastTotal) / maxF64(elapsed, 0.001)
	s.lastTotal = total
	s.lastTime = now

	parts := make([]string, 0, len(s.counts))
	for t, c := range s.counts {
		parts = append(parts, fmt.Sprintf("%s=%d", t, c))
	}
	slog.Info("Stats",
		"total", total,
		"rate_msg_s", fmt.Sprintf("%.0f", rate),
		"flushes", s.flushCount,
		"flush_rows", s.flushRows,
		"errors", s.errors,
		"parse_drops", s.parseErrors,
		"topics", strings.Join(parts, " "),
	)
}

func maxF64(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// ── DLQ buffer helper ──────────────────────────────────────────────────────

func bufferDLQEvent(
	buffers map[string]*TableBuffer,
	sourceTopic string,
	rawPayload []byte,
	errMsg string,
	stage string,
) {
	buf, ok := buffers["dead_letter_events"]
	if !ok {
		return
	}
	payload := string(rawPayload)
	if len(payload) > 10000 {
		payload = payload[:10000]
	}
	if len(errMsg) > 500 {
		errMsg = errMsg[:500]
	}
	row := []any{
		time.Now().UTC(), // timestamp
		stage,            // failed_stage
		sourceTopic,      // source_topic
		errMsg,           // error_message
		payload,          // raw_payload
		int64(0),         // retry_count
	}
	buf.Append(row)
}

// ── Internal message type for the worker pipeline ──────────────────────────

type kafkaMsg struct {
	topic     string
	partition int
	offset    int64
	value     []byte
	msg       kafka.Message // kept for offset commit
}

// ── Kafka Consumer Pipeline ────────────────────────────────────────────────

func RunConsumer(ctx context.Context, cfg *Config, pool *WriterPool) error {
	brokers := strings.Split(cfg.KafkaBrokers, ",")
	for i := range brokers {
		brokers[i] = strings.TrimSpace(brokers[i])
	}

	topics := make([]string, 0, len(topicTableMap))
	for t := range topicTableMap {
		topics = append(topics, t)
	}

	// Single reader with GroupTopics — one consumer group, all 8 topics.
	// kafka-go handles partition assignment and rebalance automatically.
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        brokers,
		GroupTopics:    topics,
		GroupID:        cfg.ConsumerGroup,
		MinBytes:       64 * 1024,        // 64 KB min fetch
		MaxBytes:       50 * 1024 * 1024, // 50 MB max fetch
		MaxWait:        100 * time.Millisecond,
		CommitInterval: 0, // manual commit only
		StartOffset:    kafka.FirstOffset,
		QueueCapacity:  cfg.PollBatch,
	})
	defer reader.Close()

	// ── Initialize buffers ──
	buffers := make(map[string]*TableBuffer)
	for table := range tableMeta {
		buffers[table] = NewTableBuffer()
	}

	stats := NewStats()
	var totalBuffered atomic.Int64

	// Track the latest consumed message per topic-partition for offset commit.
	// Only commit after a successful flush.
	var commitMu sync.Mutex
	pendingCommits := make([]kafka.Message, 0, 64)

	// Stats reporter goroutine
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				stats.Report()
			case <-ctx.Done():
				return
			}
		}
	}()

	// ── Worker pool: parse JSON + build rows in parallel ──
	numWorkers := cfg.FlushWorkers * 2
	if numWorkers < 4 {
		numWorkers = 4
	}

	msgCh := make(chan kafkaMsg, cfg.PollBatch*2)
	var workerWg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			var parser fastjson.Parser

			for msg := range msgCh {
				table, ok := topicTableMap[msg.topic]
				if !ok {
					continue
				}

				v, err := parser.ParseBytes(msg.value)
				if err != nil {
					stats.RecordParseError(1)
					bufferDLQEvent(buffers, msg.topic, msg.value, err.Error(), "json_parse")
					continue
				}

				// Inject deterministic event_id for ingestion-tier tables
				if inputTables[table] {
					eid := deterministicEventID(msg.topic, int32(msg.partition), msg.offset)
					v.Set("_event_id", fastjson.MustParse(fmt.Sprintf("%q", eid)))
				}

				meta := tableMeta[table]
				if meta == nil || meta.Builder == nil {
					continue
				}

				row := meta.Builder(v)
				buffers[table].Append(row)
				totalBuffered.Add(1)
				stats.RecordMessages(msg.topic, 1)

				// Track this message for commit
				commitMu.Lock()
				pendingCommits = append(pendingCommits, msg.msg)
				commitMu.Unlock()
			}
		}()
	}

	// ── doFlushAndCommit: non-blocking (snapshot sync, I/O in goroutine) ──
	var flushInProgress atomic.Bool
	var flushWg sync.WaitGroup

	doFlushAndCommit := func(label string) {
		if totalBuffered.Load() == 0 {
			return
		}
		if !flushInProgress.CompareAndSwap(false, true) {
			return // another flush is in-flight
		}
		totalBuffered.Store(0)

		flushWg.Add(1)
		go func() {
			defer flushWg.Done()
			defer flushInProgress.Store(false)

			flushed, ok := FlushAllParallel(ctx, pool, buffers, cfg.FlushWorkers)
			if flushed > 0 {
				stats.RecordFlush(flushed)
			}

			commitMu.Lock()
			toCommit := make([]kafka.Message, len(pendingCommits))
			copy(toCommit, pendingCommits)
			pendingCommits = pendingCommits[:0]
			commitMu.Unlock()

			if ok && len(toCommit) > 0 {
				if err := reader.CommitMessages(ctx, toCommit...); err != nil {
					slog.Warn("Offset commit failed", "trigger", label, "err", err)
				}
			} else if !ok {
				slog.Warn("Skipping offset commit — flush had errors", "trigger", label)
			}
		}()
	}

	slog.Info("Consumer running",
		"brokers", cfg.KafkaBrokers,
		"group", cfg.ConsumerGroup,
		"topics", topics,
		"workers", numWorkers,
		"flush_workers", cfg.FlushWorkers,
		"batch_size", cfg.BatchSize,
		"flush_interval", cfg.FlushInterval,
	)

	// ── Main fetch loop ──
	flushTicker := time.NewTicker(time.Duration(float64(time.Second) * cfg.FlushInterval))
	defer flushTicker.Stop()

	// Backpressure: pause fetching when buffer exceeds high watermark
	highWatermark := int64(cfg.BatchSize) * 3
	var backpressureActive bool

	for {
		select {
		case <-ctx.Done():
			goto shutdown
		case <-flushTicker.C:
			doFlushAndCommit("timer")
		default:
		}

		// Backpressure check: if buffer is too large, flush and skip fetch
		buffered := totalBuffered.Load()
		if buffered >= highWatermark {
			if !backpressureActive {
				slog.Warn("Backpressure activated — buffer exceeds high watermark",
					"buffered", buffered, "watermark", highWatermark)
				backpressureActive = true
			}
			doFlushAndCommit("backpressure")
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if backpressureActive {
			slog.Info("Backpressure released — buffer drained", "buffered", buffered)
			backpressureActive = false
		}

		// Fetch message with short timeout so we can check flush triggers
		fetchCtx, fetchCancel := context.WithTimeout(ctx, 200*time.Millisecond)
		m, err := reader.FetchMessage(fetchCtx)
		fetchCancel()
		if err != nil {
			if ctx.Err() != nil {
				goto shutdown
			}
			// Timeout or transient error — check size-based flush
			if totalBuffered.Load() >= int64(cfg.BatchSize) {
				doFlushAndCommit("size")
			}
			continue
		}

		// Push message to worker pool
		select {
		case msgCh <- kafkaMsg{
			topic:     m.Topic,
			partition: m.Partition,
			offset:    m.Offset,
			value:     m.Value,
			msg:       m,
		}:
		case <-ctx.Done():
			goto shutdown
		}

		// Size-based flush
		if totalBuffered.Load() >= int64(cfg.BatchSize) {
			doFlushAndCommit("size")
		}
	}

shutdown:
	slog.Info("Shutdown: draining workers...")
	close(msgCh)
	workerWg.Wait()
	flushWg.Wait() // wait for any in-flight flush to complete

	// Final flush with background context (no cancellation)
	flushed, ok := FlushAllParallel(context.Background(), pool, buffers, cfg.FlushWorkers)
	if flushed > 0 {
		stats.RecordFlush(flushed)
	}

	commitMu.Lock()
	toCommit := make([]kafka.Message, len(pendingCommits))
	copy(toCommit, pendingCommits)
	pendingCommits = nil
	commitMu.Unlock()

	if ok && len(toCommit) > 0 {
		if err := reader.CommitMessages(context.Background(), toCommit...); err != nil {
			slog.Warn("Final offset commit failed", "err", err)
		}
	} else if !ok {
		slog.Error("Final flush had errors — offsets NOT committed to prevent data loss")
	}

	stats.Report()
	slog.Info("Consumer shut down cleanly")
	return nil
}
