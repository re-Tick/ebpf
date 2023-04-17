package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	_ "github.com/cilium/ebpf"
)

var currentPort uint32 = 5000

const (
	proxyAddress = "0.0.0.0"
	response     = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 12\r\n\r\nHello World!"
)

var runningPorts = []uint32{}

// starts a number of proxies on the unused ports
func bootProxies() {
	log.Println("bootProxies is called")
	for i := 0; i < 50; {
		if isPortAvailable(currentPort) {
			go startProxy(currentPort)
			runningPorts = append(runningPorts, currentPort)
			i++
		}
		currentPort++
	}
	log.Println("runningPorts after booting are: ", runningPorts)
}

func isPortAvailable(port uint32) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%v", port))
	if err != nil {
		return false
	}
	defer ln.Close()
	return true
}

func startProxy(port uint32) {
	println("PID:", os.Getpid())
	listener, err := net.Listen("tcp", fmt.Sprintf(proxyAddress+":%v", port))
	if err != nil {
		log.Fatalf("Error listening on %s: %v", proxyAddress, err)
	}
	defer listener.Close()

	log.Printf("Proxy server is listening on %s", fmt.Sprintf(proxyAddress+":%v", port))

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}

		go handleConnection(conn, port)
	}
}

func handleConnection(conn net.Conn, port uint32) {
	// port := getRemotePort(conn)

	var (
	// tmpPort uint32
	// indx    uint32 = 0
	)
	// if err := objs.VaccantPorts.Lookup(uint32(0), &tmpPort); err != nil {
	// 	log.Fatalf("reading map: %v", err)
	// }
	// log.Printf("Vacant_ports %T, port at index 0: %v", objs.VaccantPorts, tmpPort)

	// if err := objs.VaccantPorts.Delete(indx); err != nil {
	// log.Fatalf("failed to delete a port from vacant_ports: %v", err)
	// }
	log.Println("port: ", port)
	// var dest Dest_info
	// if err := objs.PortMapping.Lookup(port, &dest); err != nil {
	// 	log.Printf("reading Port map: %v", err)
	// } else {
	// 	log.Printf("Value for key:[%v]: %v", port, dest)
	// }

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
