package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// tcpblaster sends pre-generated NDJSON payloads over parallel TCP connections
// at maximum speed to measure pipeline throughput independent of sender overhead.

func main() {
	host := flag.String("host", "host.docker.internal", "Target host")
	port := flag.Int("port", 9514, "Target port")
	workers := flag.Int("workers", 8, "Number of parallel TCP connections")
	duration := flag.Int("duration", 60, "Test duration in seconds")
	warmup := flag.Int("warmup", 5, "Warmup duration in seconds")
	payloadFile := flag.String("file", "/data/real_logs_payload.ndjson", "Path to NDJSON payload file")
	chunkKB := flag.Int("chunk-kb", 256, "TCP send chunk size in KB")
	flag.Parse()

	addr := fmt.Sprintf("%s:%d", *host, *port)
	chunkSize := *chunkKB * 1024

	// ── Phase 1: Load payload ────────────────────────────────────────────
	fmt.Println("══════════════════════════════════════════════════════════════")
	fmt.Println("  CLIF Go TCP Blaster — Real Log Benchmark")
	fmt.Println("══════════════════════════════════════════════════════════════")
	fmt.Printf("  Target:     %s\n", addr)
	fmt.Printf("  Workers:    %d TCP connections\n", *workers)
	fmt.Printf("  Duration:   %ds (+ %ds warmup)\n", *duration, *warmup)
	fmt.Printf("  Chunk Size: %d KB\n", *chunkKB)
	fmt.Println()

	fmt.Printf("[1/4] Loading payload from %s...\n", *payloadFile)
	payload, lineCount, err := loadPayload(*payloadFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
	sizeMB := float64(len(payload)) / (1024 * 1024)
	fmt.Printf("  Loaded: %d events, %.1f MB\n", lineCount, sizeMB)

	// ── Phase 2: Test connection ─────────────────────────────────────────
	fmt.Println("\n[2/4] Testing connection...")
	testConn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Cannot connect to %s: %v\n", addr, err)
		os.Exit(1)
	}
	testConn.Write([]byte(`{"message":"go-blaster-warmup","source_type":"benchmark"}` + "\n"))
	testConn.Close()
	fmt.Println("  ✔ Connection OK")

	// ── Phase 3: Blast ──────────────────────────────────────────────────
	fmt.Printf("\n[3/4] Blasting with %d workers for %ds (+%ds warmup)...\n",
		*workers, *duration, *warmup)

	var totalBytes int64
	var totalEvents int64
	var totalErrors int64
	var wg sync.WaitGroup

	warmupEnd := time.Now().Add(time.Duration(*warmup) * time.Second)
	measureEnd := warmupEnd.Add(time.Duration(*duration) * time.Second)

	// Split payload into per-worker chunks for better cache locality
	workerPayloads := splitPayload(payload, *workers)

	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func(workerID int, data []byte) {
			defer wg.Done()
			blastWorker(workerID, addr, data, chunkSize, warmupEnd, measureEnd,
				&totalBytes, &totalEvents, &totalErrors, lineCount, *workers)
		}(i, workerPayloads[i])
	}

	// Progress reporter
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if time.Now().After(measureEnd) {
				return
			}
			ev := atomic.LoadInt64(&totalEvents)
			elapsed := time.Since(warmupEnd).Seconds()
			if elapsed > 0 {
				fmt.Printf("  [%4.0fs] %12s events  (%s EPS)\n",
					elapsed, fmtInt(ev), fmtInt(int64(float64(ev)/elapsed)))
			}
		}
	}()

	wg.Wait()

	// ── Phase 4: Results ─────────────────────────────────────────────────
	fmt.Println("\n[4/4] Results")

	bytesSent := atomic.LoadInt64(&totalBytes)
	eventsSent := atomic.LoadInt64(&totalEvents)
	errors := atomic.LoadInt64(&totalErrors)
	durationSec := float64(*duration)
	eps := float64(eventsSent) / durationSec
	mbps := float64(bytesSent) / (1024 * 1024) / durationSec
	vectorCPUs := 6.0
	epsPerCore := eps / vectorCPUs

	fmt.Println()
	fmt.Println("══════════════════════════════════════════════════════════════")
	fmt.Println("  RESULTS — Real Logs via Go TCP Blaster")
	fmt.Println("══════════════════════════════════════════════════════════════")
	fmt.Printf("  Events Sent:       %s\n", fmtInt(eventsSent))
	fmt.Printf("  Bytes Sent:        %.1f MB\n", float64(bytesSent)/(1024*1024))
	fmt.Printf("  Duration:          %ds\n", *duration)
	fmt.Printf("  Throughput:        %.1f MB/s\n", mbps)
	fmt.Printf("  Total EPS:         %s\n", fmtInt(int64(eps)))
	fmt.Printf("  Per-Core EPS:      %s  (Vector on %.0f CPUs)\n", fmtInt(int64(epsPerCore)), vectorCPUs)
	fmt.Printf("  TCP Connections:   %d\n", *workers)
	fmt.Printf("  Send Errors:       %d\n", errors)
	fmt.Println("══════════════════════════════════════════════════════════════")
}

func loadPayload(path string) ([]byte, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, 0, err
	}

	// Count lines
	lineCount := bytes.Count(data, []byte("\n"))
	return data, lineCount, nil
}

func splitPayload(data []byte, n int) [][]byte {
	// Split by lines into n roughly equal chunks
	lines := bytes.Split(data, []byte("\n"))
	// Remove trailing empty line
	if len(lines) > 0 && len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}

	chunkSize := len(lines) / n
	result := make([][]byte, n)
	for i := 0; i < n; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if i == n-1 {
			end = len(lines)
		}
		var buf bytes.Buffer
		for _, line := range lines[start:end] {
			buf.Write(line)
			buf.WriteByte('\n')
		}
		result[i] = buf.Bytes()
	}
	return result
}

func blastWorker(id int, addr string, payload []byte, chunkSize int,
	warmupEnd, measureEnd time.Time,
	totalBytes, totalEvents, totalErrors *int64,
	lineCount, numWorkers int) {

	payloadLen := len(payload)
	if payloadLen == 0 {
		return
	}

	// Events in this worker's payload chunk
	_ = bytes.Count(payload, []byte("\n"))

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		atomic.AddInt64(totalErrors, 1)
		fmt.Fprintf(os.Stderr, "  [Worker %d] connect error: %v\n", id, err)
		return
	}
	defer conn.Close()

	// Set large send buffer
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetWriteBuffer(8 * 1024 * 1024)
	}

	writer := bufio.NewWriterSize(conn, 1024*1024) // 1MB write buffer

	offset := 0
	for {
		now := time.Now()
		if now.After(measureEnd) {
			break
		}
		measuring := now.After(warmupEnd)

		// Determine how much to send this iteration
		end := offset + chunkSize
		if end > payloadLen {
			// Wrap around: send remaining + start of payload
			remaining := payloadLen - offset
			n1, err1 := writer.Write(payload[offset:])
			if err1 != nil {
				// Reconnect
				writer.Flush()
				conn.Close()
				conn, err = net.DialTimeout("tcp", addr, 5*time.Second)
				if err != nil {
					atomic.AddInt64(totalErrors, 1)
					return
				}
				if tc, ok := conn.(*net.TCPConn); ok {
					tc.SetNoDelay(true)
					tc.SetWriteBuffer(8 * 1024 * 1024)
				}
				writer = bufio.NewWriterSize(conn, 1024*1024)
				offset = 0
				continue
			}

			// Events in the tail piece
			if measuring {
				tailEvents := bytes.Count(payload[offset:], []byte("\n"))
				atomic.AddInt64(totalBytes, int64(n1))
				atomic.AddInt64(totalEvents, int64(tailEvents))
			}

			wrapBytes := end - payloadLen
			if wrapBytes > 0 {
				n2, err2 := writer.Write(payload[:wrapBytes])
				if err2 != nil {
					offset = 0
					continue
				}
				if measuring {
					headEvents := bytes.Count(payload[:wrapBytes], []byte("\n"))
					atomic.AddInt64(totalBytes, int64(n2))
					atomic.AddInt64(totalEvents, int64(headEvents))
				}
			}
			_ = remaining
			offset = end - payloadLen
		} else {
			n, err := writer.Write(payload[offset:end])
			if err != nil {
				// Reconnect on error
				writer.Flush()
				conn.Close()
				conn, err = net.DialTimeout("tcp", addr, 5*time.Second)
				if err != nil {
					atomic.AddInt64(totalErrors, 1)
					return
				}
				if tc, ok := conn.(*net.TCPConn); ok {
					tc.SetNoDelay(true)
					tc.SetWriteBuffer(8 * 1024 * 1024)
				}
				writer = bufio.NewWriterSize(conn, 1024*1024)
				offset = 0
				continue
			}
			if measuring {
				chunkEvents := bytes.Count(payload[offset:end], []byte("\n"))
				atomic.AddInt64(totalBytes, int64(n))
				atomic.AddInt64(totalEvents, int64(chunkEvents))
			}
			offset = end
		}

		// Flush periodically (every ~4MB)
		if offset%(4*1024*1024) < chunkSize {
			writer.Flush()
		}
	}

	writer.Flush()
}

func fmtInt(n int64) string {
	if n < 0 {
		return "-" + fmtInt(-n)
	}
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	// Insert commas
	var result []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}
