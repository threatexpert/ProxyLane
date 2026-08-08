package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type logger struct {
	mu   sync.Mutex
	file *os.File
}

type replyWriter struct {
	fragment bool
	delay    time.Duration
}

func (w replyWriter) write(conn net.Conn, data []byte) error {
	if !w.fragment {
		_, err := conn.Write(data)
		return err
	}
	for _, value := range data {
		if _, err := conn.Write([]byte{value}); err != nil {
			return err
		}
		if w.delay > 0 {
			time.Sleep(w.delay)
		}
	}
	return nil
}

func (l *logger) printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.file, "%.3f ", float64(time.Now().UnixNano())/1e9)
	fmt.Fprintf(l.file, format, args...)
	fmt.Fprintln(l.file)
}

func readExact(reader io.Reader, size int) ([]byte, error) {
	data := make([]byte, size)
	_, err := io.ReadFull(reader, data)
	return data, err
}

func authenticate(reader *bufio.Reader, conn net.Conn, username, password string,
	writer replyWriter) error {
	header, err := readExact(reader, 2)
	if err != nil || header[0] != 5 {
		return fmt.Errorf("invalid greeting")
	}
	methods, err := readExact(reader, int(header[1]))
	if err != nil {
		return err
	}
	required := byte(0)
	if username != "" {
		required = 2
	}
	found := false
	for _, method := range methods {
		found = found || method == required
	}
	if !found {
		_ = writer.write(conn, []byte{5, 0xff})
		return fmt.Errorf("required authentication method unavailable")
	}
	if err = writer.write(conn, []byte{5, required}); err != nil || required == 0 {
		return err
	}
	versionAndLength, err := readExact(reader, 2)
	if err != nil {
		return err
	}
	user, err := readExact(reader, int(versionAndLength[1]))
	if err != nil {
		return err
	}
	passwordLength, err := readExact(reader, 1)
	if err != nil {
		return err
	}
	providedPassword, err := readExact(reader, int(passwordLength[0]))
	ok := err == nil && versionAndLength[0] == 1 && string(user) == username &&
		string(providedPassword) == password
	status := byte(1)
	if ok {
		status = 0
	}
	_ = writer.write(conn, []byte{1, status})
	if !ok {
		return fmt.Errorf("authentication rejected")
	}
	return nil
}

func readCommand(reader *bufio.Reader) (byte, string, int, error) {
	header, err := readExact(reader, 4)
	if err != nil || header[0] != 5 {
		return 0, "", 0, fmt.Errorf("invalid SOCKS5 request")
	}
	command := header[1]
	var host string
	switch header[3] {
	case 1:
		var address []byte
		address, err = readExact(reader, 4)
		if err == nil {
			host = net.IP(address).String()
		}
	case 3:
		length, lengthError := readExact(reader, 1)
		if lengthError != nil {
			return 0, "", 0, lengthError
		}
		var address []byte
		address, err = readExact(reader, int(length[0]))
		host = string(address)
	case 4:
		var address []byte
		address, err = readExact(reader, 16)
		if err == nil {
			host = net.IP(address).String()
		}
	default:
		return 0, "", 0, fmt.Errorf("unsupported address type %d", header[3])
	}
	if err != nil {
		return 0, "", 0, err
	}
	portBytes, err := readExact(reader, 2)
	if err != nil {
		return 0, "", 0, err
	}
	return command, host, int(binary.BigEndian.Uint16(portBytes)), nil
}

func parseRequest(packet []byte) (*net.UDPAddr, []byte, string, error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return nil, nil, "", fmt.Errorf("malformed SOCKS5 UDP header")
	}
	var host string
	var payloadOffset int
	switch packet[3] {
	case 1:
		if len(packet) < 10 {
			return nil, nil, "", io.ErrUnexpectedEOF
		}
		host = net.IP(packet[4:8]).String()
		payloadOffset = 10
	case 3:
		if len(packet) < 7 || int(packet[4])+7 > len(packet) {
			return nil, nil, "", io.ErrUnexpectedEOF
		}
		host = string(packet[5 : 5+int(packet[4])])
		payloadOffset = 7 + int(packet[4])
	case 4:
		if len(packet) < 22 {
			return nil, nil, "", io.ErrUnexpectedEOF
		}
		host = net.IP(packet[4:20]).String()
		payloadOffset = 22
	default:
		return nil, nil, "", fmt.Errorf("unsupported address type %d", packet[3])
	}
	port := int(binary.BigEndian.Uint16(packet[payloadOffset-2 : payloadOffset]))
	original := host
	if strings.HasSuffix(host, ".v6.test") {
		host = "::1"
	} else if strings.HasPrefix(host, "203.0.113.") || strings.HasSuffix(host, ".test") {
		host = "127.0.0.1"
	} else if strings.HasPrefix(host, "2001:db8:") {
		host = "::1"
	}
	network := "udp4"
	if strings.Contains(host, ":") {
		network = "udp6"
	}
	address, err := net.ResolveUDPAddr(network, net.JoinHostPort(host, fmt.Sprint(port)))
	return address, packet[payloadOffset:], original, err
}

func frame(source *net.UDPAddr, payload []byte) []byte {
	if source.IP.To4() == nil {
		packet := make([]byte, 22+len(payload))
		packet[3] = 4
		copy(packet[4:20], source.IP.To16())
		binary.BigEndian.PutUint16(packet[20:22], uint16(source.Port))
		copy(packet[22:], payload)
		return packet
	}
	packet := make([]byte, 10+len(payload))
	packet[3] = 1
	copy(packet[4:8], source.IP.To4())
	binary.BigEndian.PutUint16(packet[8:10], uint16(source.Port))
	copy(packet[10:], payload)
	return packet
}

func sameAddress(left, right *net.UDPAddr) bool {
	return left != nil && right != nil && left.Port == right.Port && left.IP.Equal(right.IP)
}

func mapHost(host string) string {
	if strings.HasSuffix(host, ".v6.test") {
		return "::1"
	}
	if strings.HasPrefix(host, "203.0.113.") || strings.HasSuffix(host, ".test") {
		return "127.0.0.1"
	}
	if strings.HasPrefix(host, "2001:db8:") {
		return "::1"
	}
	return host
}

func handleConnect(conn net.Conn, reader *bufio.Reader, host string, port int,
	writer replyWriter, log *logger) {
	target := net.JoinHostPort(mapHost(host), fmt.Sprint(port))
	network := "tcp4"
	if strings.Contains(mapHost(host), ":") {
		network = "tcp6"
	}
	upstream, err := net.DialTimeout(network, target, 5*time.Second)
	if err != nil {
		_ = writer.write(conn, []byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		log.printf("CONNECT ERROR target=%s error=%v", target, err)
		return
	}
	defer upstream.Close()
	if err = writer.write(conn, []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}
	log.printf("CONNECT READY original=%s target=%s", net.JoinHostPort(host,
		fmt.Sprint(port)), target)
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		_, _ = io.Copy(upstream, reader)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	go func() {
		defer wait.Done()
		_, _ = io.Copy(conn, upstream)
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	wait.Wait()
	log.printf("CONNECT CLOSED original=%s", net.JoinHostPort(host, fmt.Sprint(port)))
}

func handleAssociation(conn net.Conn, reader *bufio.Reader, writer replyWriter,
	log *logger) {
	command, _, _, err := readCommand(reader)
	if err != nil || command != 3 {
		log.printf("ASSOC ERROR %v command=%d", err, command)
		return
	}
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		log.printf("ASSOC ERROR %v", err)
		return
	}
	defer relay.Close()
	relayAddress := relay.LocalAddr().(*net.UDPAddr)
	reply := make([]byte, 10)
	reply[0] = 5
	reply[3] = 1
	copy(reply[4:8], relayAddress.IP.To4())
	binary.BigEndian.PutUint16(reply[8:10], uint16(relayAddress.Port))
	if err = writer.write(conn, reply); err != nil {
		return
	}
	log.printf("ASSOC READY relay=%d", relayAddress.Port)
	go func() {
		_, _ = io.Copy(io.Discard, reader)
		_ = relay.Close()
	}()
	buffer := make([]byte, 65535)
	type upstreamRoute struct {
		conn     *net.UDPConn
		reported *net.UDPAddr
	}
	routes := make(map[string]*upstreamRoute)
	defer func() {
		for _, route := range routes {
			_ = route.conn.Close()
		}
	}()
	var client *net.UDPAddr
	for {
		count, source, readError := relay.ReadFromUDP(buffer)
		if readError != nil {
			break
		}
		if client == nil {
			client = source
		} else if !sameAddress(client, source) {
			log.printf("UDP ERROR unexpected client=%s expected=%s", source, client)
			continue
		}
		target, payload, original, parseError := parseRequest(buffer[:count])
		if parseError != nil {
			log.printf("UDP ERROR parse=%v", parseError)
			continue
		}
		key := target.String()
		route := routes[key]
		if route == nil {
			network := "udp4"
			if target.IP.To4() == nil {
				network = "udp6"
			}
			upstream, dialError := net.DialUDP(network, nil, target)
			if dialError != nil {
				log.printf("UDP ERROR original=%s target=%s error=%v", original, target, dialError)
				continue
			}
			reportedSource := target
			if originalIP := net.ParseIP(original); originalIP != nil {
				reportedSource = &net.UDPAddr{IP: originalIP, Port: target.Port}
			}
			route = &upstreamRoute{conn: upstream, reported: reportedSource}
			routes[key] = route
			go func(active *upstreamRoute, app *net.UDPAddr) {
				response := make([]byte, 65535)
				for {
					responseLength, _, responseError := active.conn.ReadFromUDP(response)
					if responseError != nil {
						return
					}
					_, _ = relay.WriteToUDP(frame(active.reported,
						response[:responseLength]), app)
				}
			}(route, client)
		}
		if _, writeError := route.conn.Write(payload); writeError != nil {
			log.printf("UDP ERROR original=%s write=%v", original, writeError)
		}
	}
	log.printf("ASSOC CLOSED relay=%d", relayAddress.Port)
}

func handleClient(conn net.Conn, username, password string, writer replyWriter,
	log *logger) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	if err := authenticate(reader, conn, username, password, writer); err != nil {
		log.printf("AUTH ERROR %v", err)
		return
	}
	peek, err := reader.Peek(2)
	if err != nil {
		log.printf("REQUEST ERROR %v", err)
		return
	}
	if peek[0] != 5 {
		log.printf("REQUEST ERROR invalid version")
		return
	}
	if peek[1] == 3 {
		handleAssociation(conn, reader, writer, log)
		return
	}
	command, host, port, err := readCommand(reader)
	if err != nil || command != 1 {
		log.printf("CONNECT ERROR command=%d error=%v", command, err)
		return
	}
	handleConnect(conn, reader, host, port, writer, log)
}

func main() {
	listen := flag.String("listen", "127.0.0.1:7800", "TCP listen address")
	logPath := flag.String("log", "socks5-go.log", "association log")
	username := flag.String("username", "", "optional username")
	password := flag.String("password", "", "optional password")
	fragmentReplies := flag.Bool("fragment-replies", false,
		"write SOCKS5 replies one byte at a time")
	fragmentDelay := flag.Duration("fragment-delay", time.Millisecond,
		"delay between fragmented reply bytes")
	flag.Parse()
	file, err := os.Create(*logPath)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	log := &logger{file: file}
	writer := replyWriter{fragment: *fragmentReplies, delay: *fragmentDelay}
	listener, err := net.Listen("tcp4", *listen)
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	log.printf("LISTEN %s", *listen)
	for {
		conn, acceptError := listener.Accept()
		if acceptError != nil {
			panic(acceptError)
		}
		go handleClient(conn, *username, *password, writer, log)
	}
}
