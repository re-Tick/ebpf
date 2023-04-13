package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	_"github.com/cilium/ebpf"
)

const (
	proxyAddress = "0.0.0.0:80"
	response     = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 12\r\n\r\nHello World!"
)

func startProxy() {
	println("PID:", os.Getpid())
	listener, err := net.Listen("tcp", proxyAddress)
	if err != nil {
		log.Fatalf("Error listening on %s: %v", proxyAddress, err)
	}
	defer listener.Close()

	log.Printf("Proxy server is listening on %s", proxyAddress)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	port := getRemotePort(conn)

	fmt.Println("port: ", port)

	// var value uint32
	// 	if err := port_access.Lookup(port, &value); err != nil {
	// 		// log.Fatal("unable to read Port_access map: %v", err)
	// 		fmt.Printf("unable to read port_access map: %v",err)
	// 	}else{
	// 		fmt.Println("Destination information: ", value)
	// 	}


	fmt.Println("metadata about the connection", conn.RemoteAddr(), conn.LocalAddr())
	defer conn.Close()

	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("Error reading from connection: %v", err)
			break
		}
		fmt.Printf("Received message: %s", line)
		if line == "\r\n" {
			break
		}
	}

	_, err := conn.Write([]byte(response))
	if err != nil {
		log.Printf("Error writing response: %v", err)
	}
}

func getRemotePort(conn net.Conn) int {
	addr := conn.RemoteAddr().(*net.TCPAddr)
	return addr.Port
}
