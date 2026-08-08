package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

func payload(sequence, size int) []byte {
	data := make([]byte, size)
	for index := range data {
		data[index] = byte(sequence*31 + index*17)
	}
	return data
}

func handleServer(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	request, err := io.ReadAll(conn)
	if err != nil {
		return
	}
	reply := append([]byte("HALF-CLOSE-ACK:"), request...)
	_, _ = conn.Write(reply)
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
}

func runServer(network, listen, output string) error {
	listener, err := net.Listen(network, listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	if output != "" {
		if err = os.WriteFile(output, []byte("TCP_SERVER_READY\n"), 0o644); err != nil {
			return err
		}
	}
	for {
		conn, acceptError := listener.Accept()
		if acceptError != nil {
			return acceptError
		}
		go handleServer(conn)
	}
}

func oneRoundTrip(network, target string, sequence, size int, expectedPrefix []byte) error {
	conn, err := net.DialTimeout(network, target, 10*time.Second)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if len(expectedPrefix) > 0 {
		prefix := make([]byte, len(expectedPrefix))
		if _, err = io.ReadFull(conn, prefix); err != nil {
			return fmt.Errorf("read initial prefix: %w", err)
		}
		if !bytes.Equal(prefix, expectedPrefix) {
			return fmt.Errorf("initial prefix mismatch")
		}
	}
	request := payload(sequence, size)
	if _, err = conn.Write(request); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("connection is not TCP")
	}
	if err = tcp.CloseWrite(); err != nil {
		return fmt.Errorf("close write: %w", err)
	}
	reply, err := io.ReadAll(conn)
	if err != nil {
		return fmt.Errorf("read reply: %w", err)
	}
	expected := append([]byte("HALF-CLOSE-ACK:"), request...)
	if !bytes.Equal(reply, expected) {
		prefix := bytes.HasPrefix(reply, []byte("HALF-CLOSE-ACK:"))
		return fmt.Errorf("reply mismatch: got=%d expected=%d ack-prefix=%t",
			len(reply), len(expected), prefix)
	}
	return nil
}

func runClient(network, target, output string, connections, iterations int,
	expectedPrefix []byte) error {
	started := time.Now()
	errors := make(chan error, connections)
	var wait sync.WaitGroup
	for connection := 0; connection < connections; connection++ {
		wait.Add(1)
		go func(connection int) {
			defer wait.Done()
			for iteration := 0; iteration < iterations; iteration++ {
				sizes := []int{0, 1, 512, 16384, 65536}
				sequence := connection*iterations + iteration
				if err := oneRoundTrip(network, target, sequence, sizes[sequence%len(sizes)],
					expectedPrefix); err != nil {
					errors <- fmt.Errorf("connection=%d iteration=%d: %w",
						connection, iteration, err)
					return
				}
			}
		}(connection)
	}
	wait.Wait()
	close(errors)
	if err := <-errors; err != nil {
		return err
	}
	summary := fmt.Sprintf("TCP_E2E_PASS connections=%d iterations=%d duration=%s\n",
		connections, iterations, time.Since(started))
	if output == "" {
		fmt.Print(summary)
		return nil
	}
	return os.WriteFile(output, []byte(summary), 0o644)
}

func main() {
	mode := flag.String("mode", "client", "server or client")
	network := flag.String("network", "tcp", "tcp, tcp4, or tcp6")
	listen := flag.String("listen", "127.0.0.1:39003", "server listen address")
	target := flag.String("target", "203.0.113.10:39003", "client target address")
	output := flag.String("output", "", "ready/result file")
	connections := flag.Int("connections", 8, "parallel client connections")
	iterations := flag.Int("iterations", 10, "round trips per connection")
	expectPrefix := flag.String("expect-prefix", "",
		"bytes expected immediately after connect")
	flag.Parse()
	var err error
	if *mode == "server" {
		err = runServer(*network, *listen, *output)
	} else {
		err = runClient(*network, *target, *output, *connections, *iterations,
			[]byte(*expectPrefix))
	}
	if err != nil {
		result := "TCP_E2E_FAIL " + err.Error() + "\n"
		if *output != "" {
			_ = os.WriteFile(*output, []byte(result), 0o644)
		}
		fmt.Fprint(os.Stderr, result)
		os.Exit(1)
	}
}
