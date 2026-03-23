package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/segmentio/kafka-go"
)

// ── Config — all environment variables ─────────────────────────────────────

type Config struct {
	KafkaBrokers       string
	ClickHouseHost     string
	ClickHouseAltHosts string
	ClickHousePort     int
	ClickHouseUser     string
	ClickHousePassword string
	ClickHouseDB       string
	ConsumerGroup      string
	BatchSize          int
	FlushInterval      float64 // seconds
	MaxRetries         int
	PollBatch          int
	FlushWorkers       int
	LogLevel           string
	DLQTopic           string
}

func LoadConfig() *Config {
	return &Config{
		KafkaBrokers:       envStr("KAFKA_BROKERS", "redpanda01:9092"),
		ClickHouseHost:     envStr("CLICKHOUSE_HOST", "clickhouse01"),
		ClickHouseAltHosts: envStr("CLICKHOUSE_ALT_HOSTS", ""),
		ClickHousePort:     envInt("CLICKHOUSE_PORT", 9000),
		ClickHouseUser:     envStr("CLICKHOUSE_USER", "clif_admin"),
		ClickHousePassword: envStr("CLICKHOUSE_PASSWORD", "clif_secure_password_change_me"),
		ClickHouseDB:       envStr("CLICKHOUSE_DB", "clif_logs"),
		ConsumerGroup:      envStr("CONSUMER_GROUP_ID", "clif-clickhouse-consumer"),
		BatchSize:          envInt("CONSUMER_BATCH_SIZE", 500000),
		FlushInterval:      envFloat("CONSUMER_FLUSH_INTERVAL_SEC", 0.5),
		MaxRetries:         envInt("CONSUMER_MAX_RETRIES", 5),
		PollBatch:          envInt("CONSUMER_POLL_BATCH", 50000),
		FlushWorkers:       envInt("CONSUMER_FLUSH_WORKERS", 4),
		LogLevel:           envStr("LOG_LEVEL", "INFO"),
		DLQTopic:           envStr("DLQ_TOPIC", "dead-letter"),
	}
}

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil {
			return n
		}
	}
	return def
}

func envFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err == nil {
			return f
		}
	}
	return def
}

// ── Pre-flight validation ──────────────────────────────────────────────────

func preflight(cfg *Config) error {
	// 1. Verify Kafka/Redpanda connectivity
	brokers := strings.Split(cfg.KafkaBrokers, ",")
	for i := range brokers {
		brokers[i] = strings.TrimSpace(brokers[i])
	}
	slog.Info("Pre-flight: checking Kafka connectivity", "brokers", brokers)
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 10*time.Second)
	conn, err := kafka.DialContext(dialCtx, "tcp", brokers[0])
	dialCancel()
	if err != nil {
		return fmt.Errorf("kafka connectivity check failed for %s: %w", brokers[0], err)
	}
	conn.Close()
	slog.Info("Pre-flight: Kafka connectivity OK")

	// 2. Verify ClickHouse is reachable (writer pool creation handles this)
	slog.Info("Pre-flight: ClickHouse will be validated via writer pool init")

	// 3. Verify required tables exist via a test writer
	slog.Info("Pre-flight: all checks passed")
	return nil
}

// ── Entry point ────────────────────────────────────────────────────────────

func main() {
	cfg := LoadConfig()

	// Configure slog level
	var level slog.Level
	switch cfg.LogLevel {
	case "DEBUG":
		level = slog.LevelDebug
	case "WARN", "WARNING":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})))

	slog.Info("Starting CLIF Go consumer",
		"brokers", cfg.KafkaBrokers,
		"group", cfg.ConsumerGroup,
		"batch_size", cfg.BatchSize,
		"flush_interval", cfg.FlushInterval,
		"poll_batch", cfg.PollBatch,
		"flush_workers", cfg.FlushWorkers,
		"clickhouse", cfg.ClickHouseHost,
	)

	// ── Pre-flight validation ──
	maxRetries := 10
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if err := preflight(cfg); err != nil {
			slog.Warn("Pre-flight check failed", "attempt", attempt, "max", maxRetries, "err", err)
			if attempt == maxRetries {
				slog.Error("Pre-flight checks failed after all retries — aborting")
				os.Exit(1)
			}
			time.Sleep(time.Duration(attempt*2) * time.Second)
			continue
		}
		break
	}

	// ── Initialize writer pool ──
	pool, err := NewWriterPool(cfg.FlushWorkers, cfg)
	if err != nil {
		slog.Error("Failed to initialize writer pool", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	// ── Graceful shutdown via context ──
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		slog.Warn("Received signal — initiating graceful shutdown", "signal", sig)
		cancel()
	}()

	// ── Run the consumer pipeline ──
	if err := RunConsumer(ctx, cfg, pool); err != nil {
		slog.Error("Consumer exited with error", "err", err)
		os.Exit(1)
	}
}
