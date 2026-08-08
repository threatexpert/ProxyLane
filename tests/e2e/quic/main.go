package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	quic "github.com/quic-go/quic-go"
)

const alpn = "proxylane-quic-e2e"

func serverTLSConfig() (*tls.Config, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ProxyLane QUIC E2E"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"quic.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{alpn}}, nil
}

func clientTLSConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, NextProtos: []string{alpn}} // test certificate
}

func echoStream(stream *quic.Stream) {
	defer stream.Close()
	_, _ = io.Copy(stream, stream)
}

func handleConnection(connection *quic.Conn) {
	go func() {
		for {
			packet, err := connection.ReceiveDatagram(context.Background())
			if err != nil {
				return
			}
			if err = connection.SendDatagram(packet); err != nil {
				return
			}
		}
	}()
	for {
		stream, err := connection.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go echoStream(stream)
	}
}

func runServer(listen, output string) error {
	tlsConfig, err := serverTLSConfig()
	if err != nil {
		return err
	}
	listener, err := quic.ListenAddr(listen, tlsConfig,
		&quic.Config{EnableDatagrams: true})
	if err != nil {
		return err
	}
	defer listener.Close()
	if output != "" {
		if err = os.WriteFile(output, []byte("QUIC_SERVER_READY\n"), 0o644); err != nil {
			return err
		}
	}
	for {
		connection, acceptError := listener.Accept(context.Background())
		if acceptError != nil {
			return acceptError
		}
		go handleConnection(connection)
	}
}

func makePayload(sequence, size int) []byte {
	data := make([]byte, size)
	for index := range data {
		data[index] = byte(sequence*29 + index*17)
	}
	return data
}

func equal(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func runClient(target, output string, iterations int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	started := time.Now()
	connection, err := quic.DialAddr(ctx, target, clientTLSConfig(),
		&quic.Config{EnableDatagrams: true})
	if err != nil {
		return fmt.Errorf("QUIC handshake: %w", err)
	}
	defer connection.CloseWithError(0, "test complete")
	stream, err := connection.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	sizes := []int{1, 512, 1200, 1472, 4096, 16384}
	for sequence := 0; sequence < iterations; sequence++ {
		payload := makePayload(sequence, sizes[sequence%len(sizes)])
		if _, err = stream.Write(payload); err != nil {
			return fmt.Errorf("stream write %d: %w", sequence, err)
		}
		reply := make([]byte, len(payload))
		if _, err = io.ReadFull(stream, reply); err != nil {
			return fmt.Errorf("stream read %d: %w", sequence, err)
		}
		if !equal(reply, payload) {
			return fmt.Errorf("stream payload mismatch %d", sequence)
		}
	}
	for sequence := 0; sequence < iterations; sequence++ {
		payload := makePayload(sequence+iterations, 1200)
		if err = connection.SendDatagram(payload); err != nil {
			return fmt.Errorf("datagram write %d: %w", sequence, err)
		}
		reply, receiveError := connection.ReceiveDatagram(ctx)
		if receiveError != nil {
			return fmt.Errorf("datagram read %d: %w", sequence, receiveError)
		}
		if !equal(reply, payload) {
			return fmt.Errorf("datagram payload mismatch %d", sequence)
		}
	}
	summary := fmt.Sprintf("QUIC_E2E_PASS streams=%d datagrams=%d duration=%s\n",
		iterations, iterations, time.Since(started))
	if output == "" {
		fmt.Print(summary)
		return nil
	}
	return os.WriteFile(output, []byte(summary), 0o644)
}

func main() {
	mode := flag.String("mode", "client", "server or client")
	listen := flag.String("listen", "0.0.0.0:39002", "server listen address")
	target := flag.String("target", "203.0.113.10:39002", "client target address")
	output := flag.String("output", "", "ready/result file")
	iterations := flag.Int("iterations", 100, "stream and datagram echoes")
	startupDelay := flag.Duration("startup-delay", 0, "diagnostic delay before networking")
	flag.Parse()
	if *startupDelay > 0 {
		if *output != "" {
			_ = os.WriteFile(*output, []byte(fmt.Sprintf("QUIC_STARTING pid=%d\n", os.Getpid())), 0o644)
		}
		time.Sleep(*startupDelay)
	}
	var err error
	if *mode == "server" {
		err = runServer(*listen, *output)
	} else {
		err = runClient(*target, *output, *iterations)
	}
	if err != nil {
		if *output != "" {
			_ = os.WriteFile(*output, []byte("QUIC_E2E_FAIL "+err.Error()+"\n"), 0o644)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
