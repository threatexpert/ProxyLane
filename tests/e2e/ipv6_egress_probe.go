package main

import (
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

func tcpProbe(target, serverName string, timeout time.Duration) error {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp6", target, &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.Handshake()
}

func tcpDNSProbe(network, target string, timeout time.Duration) error {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial(network, target)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	const id = 0x6a20
	query := dnsQuery(id)
	request := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(request[:2], uint16(len(query)))
	copy(request[2:], query)
	if _, err = conn.Write(request); err != nil {
		return err
	}
	lengthBytes := make([]byte, 2)
	if _, err = io.ReadFull(conn, lengthBytes); err != nil {
		return err
	}
	reply := make([]byte, int(binary.BigEndian.Uint16(lengthBytes)))
	if _, err = io.ReadFull(conn, reply); err != nil {
		return err
	}
	if len(reply) < 12 || binary.BigEndian.Uint16(reply[:2]) != id ||
		binary.BigEndian.Uint16(reply[2:4])&0x8000 == 0 {
		return fmt.Errorf("invalid TCP DNS response (%d bytes)", len(reply))
	}
	return nil
}

func dnsQuery(id uint16) []byte {
	packet := make([]byte, 0, 64)
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], id)
	binary.BigEndian.PutUint16(header[2:4], 0x0100)
	binary.BigEndian.PutUint16(header[4:6], 1)
	packet = append(packet, header...)
	for _, label := range []string{"example", "com"} {
		packet = append(packet, byte(len(label)))
		packet = append(packet, label...)
	}
	packet = append(packet, 0, 0, 1, 0, 1)
	return packet
}

func udpProbe(network, target string, timeout time.Duration) error {
	address, err := net.ResolveUDPAddr(network, target)
	if err != nil {
		return err
	}
	conn, err := net.DialUDP(network, nil, address)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	const id = 0x6a21
	if _, err = conn.Write(dnsQuery(id)); err != nil {
		return err
	}
	reply := make([]byte, 4096)
	count, err := conn.Read(reply)
	if err != nil {
		return err
	}
	if count < 12 || binary.BigEndian.Uint16(reply[0:2]) != id ||
		binary.BigEndian.Uint16(reply[2:4])&0x8000 == 0 {
		return fmt.Errorf("invalid DNS response (%d bytes)", count)
	}
	return nil
}

func main() {
	mode := flag.String("mode", "tcp", "tcp, tcp-tls, or udp")
	network := flag.String("network", "", "tcp4/tcp6 or udp4/udp6; inferred when empty")
	target := flag.String("target", "[2606:4700:4700::1001]:53", "IPv6 target")
	serverName := flag.String("server-name", "cloudflare-dns.com", "TLS server name")
	timeout := flag.Duration("timeout", 10*time.Second, "operation timeout")
	output := flag.String("output", "", "optional result file")
	flag.Parse()
	var err error
	if *mode == "udp" {
		selectedNetwork := *network
		if selectedNetwork == "" {
			selectedNetwork = "udp6"
		}
		err = udpProbe(selectedNetwork, *target, *timeout)
	} else if *mode == "tcp-tls" {
		err = tcpProbe(*target, *serverName, *timeout)
	} else {
		selectedNetwork := *network
		if selectedNetwork == "" {
			selectedNetwork = "tcp6"
		}
		err = tcpDNSProbe(selectedNetwork, *target, *timeout)
	}
	result := fmt.Sprintf("IPV6_EGRESS_%s_PASS target=%s\n", *mode, *target)
	if err != nil {
		result = fmt.Sprintf("IPV6_EGRESS_%s_FAIL target=%s error=%v\n",
			*mode, *target, err)
	}
	if *output != "" {
		_ = os.WriteFile(*output, []byte(result), 0o644)
	} else {
		fmt.Print(result)
	}
	if err != nil {
		os.Exit(1)
	}
}
