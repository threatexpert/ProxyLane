package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type safeLog struct {
	mu   sync.Mutex
	file *os.File
}

func (log *safeLog) printf(format string, args ...any) {
	log.mu.Lock()
	defer log.mu.Unlock()
	fmt.Fprintf(log.file, "%.3f ", float64(time.Now().UnixNano())/1e9)
	fmt.Fprintf(log.file, format, args...)
	fmt.Fprintln(log.file)
}

func mappedTarget(target string) string {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return target
	}
	if strings.HasPrefix(host, "203.0.113.") || strings.HasSuffix(host, ".test") {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func closeWrite(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
}

func handleHTTPConnect(client net.Conn, surplus string, log *safeLog) {
	defer client.Close()
	reader := bufio.NewReader(client)
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Fields(requestLine)
	if len(parts) < 3 || !strings.EqualFold(parts[0], "CONNECT") {
		return
	}
	for {
		line, readError := reader.ReadString('\n')
		if readError != nil {
			return
		}
		if line == "\r\n" {
			break
		}
	}
	original := parts[1]
	target := mappedTarget(original)
	upstream, err := net.DialTimeout("tcp4", target, 5*time.Second)
	if err != nil {
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		log.printf("CONNECT ERROR original=%s error=%v", original, err)
		return
	}
	defer upstream.Close()
	// Deliberately coalesce tunnel bytes with the final response header.
	response := "HTTP/1.1 200 Connection Established\r\nProxy-Agent: ProxyLane-E2E\r\n\r\n" + surplus
	if _, err = client.Write([]byte(response)); err != nil {
		return
	}
	log.printf("CONNECT READY original=%s target=%s surplus=%d", original, target,
		len(surplus))
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		_, _ = io.Copy(upstream, reader)
		closeWrite(upstream)
	}()
	go func() {
		defer wait.Done()
		_, _ = io.Copy(client, upstream)
		closeWrite(client)
	}()
	wait.Wait()
	log.printf("CONNECT CLOSED original=%s", original)
}

func main() {
	listen := flag.String("listen", "127.0.0.1:7804", "HTTP proxy listen address")
	logPath := flag.String("log", "http-connect-e2e.log", "server log")
	surplus := flag.String("surplus", "HTTP-SURPLUS-PRESERVED", "coalesced tunnel bytes")
	flag.Parse()
	file, err := os.Create(*logPath)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	log := &safeLog{file: file}
	listener, err := net.Listen("tcp4", *listen)
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	log.printf("LISTEN %s", *listen)
	for {
		client, acceptError := listener.Accept()
		if acceptError != nil {
			panic(acceptError)
		}
		go handleHTTPConnect(client, *surplus, log)
	}
}
