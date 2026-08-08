package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	targetFlag := flag.String("target", "203.0.113.10:39001", "UDP target")
	network := flag.String("network", "udp4", "udp4 or udp6")
	count := flag.Int("count", 1, "number of connected UDP sockets")
	hold := flag.Duration("hold", 5*time.Second, "time to keep the sockets open")
	write := flag.Bool("write", false, "send one datagram on each socket")
	flag.Parse()

	if *count < 1 {
		fmt.Fprintln(os.Stderr, "count must be positive")
		os.Exit(2)
	}
	target, err := net.ResolveUDPAddr(*network, *targetFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	connections := make([]*net.UDPConn, 0, *count)
	for index := 0; index < *count; index++ {
		connection, dialError := net.DialUDP(*network, nil, target)
		if dialError != nil {
			fmt.Fprintf(os.Stderr, "dial %d: %v\n", index, dialError)
			for _, active := range connections {
				_ = active.Close()
			}
			os.Exit(1)
		}
		connections = append(connections, connection)
		fmt.Printf("UDP_CONNECT_PROBE socket=%d local=%s remote=%s write=%t\n",
			index, connection.LocalAddr(), connection.RemoteAddr(), *write)
		if *write {
			if _, writeError := connection.Write([]byte("UDP-CONNECT-PROBE")); writeError != nil {
				fmt.Fprintf(os.Stderr, "write %d: %v\n", index, writeError)
				os.Exit(1)
			}
		}
	}

	time.Sleep(*hold)
	for _, connection := range connections {
		_ = connection.Close()
	}
	fmt.Printf("UDP_CONNECT_PROBE_PASS sockets=%d write=%t\n", *count, *write)
}
