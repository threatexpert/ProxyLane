package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

func payload(worker, sequence, size int) []byte {
	if size < 12 {
		size = 12
	}
	data := make([]byte, size)
	binary.BigEndian.PutUint32(data[0:4], uint32(worker))
	binary.BigEndian.PutUint64(data[4:12], uint64(sequence))
	for i := 12; i < len(data); i++ {
		data[i] = byte(worker*17 + sequence*31 + i)
	}
	return data
}

func equal(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func worker(network string, id, iterations int, target *net.UDPAddr, timeout time.Duration,
	pace time.Duration, latencies chan<- time.Duration, failures *atomic.Int64,
	diagnostics io.Writer, wg *sync.WaitGroup) {
	defer wg.Done()
	connected := id%2 == 0
	var conn *net.UDPConn
	var err error
	if connected {
		conn, err = net.DialUDP(network, nil, target)
	} else {
		conn, err = net.ListenUDP(network, nil)
	}
	if err != nil {
		failures.Add(int64(iterations))
		fmt.Fprintf(diagnostics, "worker %d socket: %v\n", id, err)
		return
	}
	defer conn.Close()
	sizes := []int{32, 512, 1200, 1472, 4096}
	received := make([]byte, 8192)
	for sequence := 0; sequence < iterations; sequence++ {
		iterationStarted := time.Now()
		data := payload(id, sequence, sizes[(id+sequence)%len(sizes)])
		started := time.Now()
		_ = conn.SetDeadline(started.Add(timeout))
		if connected {
			_, err = conn.Write(data)
		} else {
			_, err = conn.WriteToUDP(data, target)
		}
		if err == nil {
			var count int
			if connected {
				count, err = conn.Read(received)
			} else {
				count, _, err = conn.ReadFromUDP(received)
			}
			if err == nil && !equal(received[:count], data) {
				err = fmt.Errorf("payload mismatch: got %d want %d", count, len(data))
			}
		}
		if err != nil {
			failures.Add(1)
			fmt.Fprintf(diagnostics, "worker %d sequence %d: %v\n", id, sequence, err)
			if remaining := pace - time.Since(iterationStarted); remaining > 0 {
				time.Sleep(remaining)
			}
			continue
		}
		latencies <- time.Since(started)
		if remaining := pace - time.Since(iterationStarted); remaining > 0 {
			time.Sleep(remaining)
		}
	}
}

func percentile(sorted []time.Duration, percentage float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	index := int(float64(len(sorted)-1) * percentage)
	return sorted[index]
}

func main() {
	targetFlag := flag.String("target", "203.0.113.10:39001", "UDP echo target")
	network := flag.String("network", "udp4", "udp4 or udp6")
	workers := flag.Int("workers", 32, "concurrent UDP sockets")
	iterations := flag.Int("iterations", 250, "round trips per socket")
	timeout := flag.Duration("timeout", 3*time.Second, "per-datagram timeout")
	pace := flag.Duration("pace", 0, "minimum interval between each worker's datagrams")
	outputPath := flag.String("output", "", "optional result log path")
	flag.Parse()
	var output io.Writer = os.Stdout
	var outputFile *os.File
	if *outputPath != "" {
		var openError error
		outputFile, openError = os.Create(*outputPath)
		if openError != nil {
			fmt.Fprintln(os.Stderr, openError)
			os.Exit(2)
		}
		defer outputFile.Close()
		output = outputFile
	}
	target, err := net.ResolveUDPAddr(*network, *targetFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	latencies := make(chan time.Duration, *workers**iterations)
	var failures atomic.Int64
	var wg sync.WaitGroup
	started := time.Now()
	for id := 0; id < *workers; id++ {
		wg.Add(1)
		go worker(*network, id, *iterations, target, *timeout, *pace, latencies, &failures,
			output, &wg)
	}
	wg.Wait()
	close(latencies)
	values := make([]time.Duration, 0, len(latencies))
	for value := range latencies {
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	total := int64(*workers * *iterations)
	failureCount := failures.Load()
	fmt.Fprintf(output, "UDP_SOAK total=%d success=%d failures=%d duration=%s p50=%s p95=%s p99=%s\n",
		total, total-failureCount, failureCount, time.Since(started),
		percentile(values, .50), percentile(values, .95), percentile(values, .99))
	if failureCount != 0 {
		os.Exit(1)
	}
}
