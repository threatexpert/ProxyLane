package main

import (
	"flag"
	"fmt"
	"net"
	"os"
)

func main() {
	network := flag.String("network", "udp4", "udp4 or udp6")
	listen := flag.String("listen", "127.0.0.1:39001", "listen address")
	ready := flag.String("ready", "", "optional ready file")
	flag.Parse()
	address, err := net.ResolveUDPAddr(*network, *listen)
	if err != nil {
		panic(err)
	}
	conn, err := net.ListenUDP(*network, address)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	if *ready != "" {
		if err = os.WriteFile(*ready, []byte("UDP_ECHO_READY\n"), 0o644); err != nil {
			panic(err)
		}
	}
	buffer := make([]byte, 65535)
	for {
		count, source, readError := conn.ReadFromUDP(buffer)
		if readError != nil {
			panic(readError)
		}
		if _, err = conn.WriteToUDP(buffer[:count], source); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
}
