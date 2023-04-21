package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/cilium/ebpf"
	// "go.mongodb.org/mongo-driver/x/bsonx/bsoncore"
	"go.mongodb.org/mongo-driver/bson"
	// "go.mongodb.org/mongo-driver/bson/primitive"
	// _ "github.com/cilium/ebpf"
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

	// fmt.Println("Proxy server listening on port 27017...")

	// for {
	// 	// Accept incoming client connections
	// 	clientConn, err := listener.Accept()
	// 	if err != nil {
	// 		fmt.Println(err)
	// 		continue
	// 	}

	// 	// Connect to the original MongoDB server
	// 	serverConn, err := net.Dial("tcp", "localhost:27017")
	// 	if err != nil {
	// 		log.Println("failed to connct to mongo: ", err)
	// 		continue
	// 	}

	// 	log.Println("connectec to mongo")

	// 	// Start a goroutine to handle traffic in both directions
	// 	go func() {
	// 		log.Println("into client to server")

	// 		// Copy traffic from client to server
	// 		_, err := io.Copy(serverConn, clientConn)
	// 		if err != nil {
	// 			fmt.Println(err)
	// 		}
	// 		// Close the server connection when finished
	// 		serverConn.Close()
	// 	}()

	// 	go func() {
	// 		// Copy traffic from server to client
	// 		var buf bytes.Buffer
	// 		_, err := io.Copy(&buf, serverConn)
	// 		if err != nil {
	// 			fmt.Println(err)
	// 		}
	// 		// Parse the MongoDB wire protocol message
	// 		msgLen := binary.LittleEndian.Uint32(buf.Bytes()[0:4])
	// 		opCode := buf.Bytes()[12]
	// 		payload := buf.Bytes()[16:msgLen]

	// 		fmt.Printf("Received MongoDB message with opcode %v and payload %v\n", opCode, payload)

	// 		_, err = io.Copy(clientConn, &buf)
	// 		if err != nil {
	// 			fmt.Println(err)
	// 		}
	// 		// Close the client connection when finished
	// 		clientConn.Close()
	// 	}()
	// }

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}

		go handleConnection(conn, port)
	}
}

// func handleConnection(conn net.Conn) {
// 	// Read the client-to-server message
// 	buffer := make([]byte, 4096)
// 	n, err := conn.Read(buffer)
// 	if err != nil {
// 		log.Println(err)
// 		conn.Close()
// 		return
// 	}

// 	// Log the client-to-server message
// 	log.Printf("Received message from client:\n%s\n", string(buffer[:n]))

// 	// Forward the message to the MongoDB server
// 	mongoConn, err := net.Dial("tcp", "localhost:27017")
// 	if err != nil {
// 		log.Println(err)
// 		conn.Close()
// 		return
// 	}
// 	defer mongoConn.Close()

// 	_, err = mongoConn.Write(buffer[:n])
// 	if err != nil {
// 		log.Println(err)
// 		conn.Close()
// 		return
// 	}

// 	// Read the server-to-client response
// 	n, err = mongoConn.Read(buffer)
// 	if err != nil {
// 		log.Println(err)
// 		conn.Close()
// 		return
// 	}

// 	// Log the server-to-client response
// 	log.Printf("Received message from server:\n%s\n", string(buffer[:n]))

// 	// Forward the response to the client
// 	_, err = conn.Write(buffer[:n])
// 	if err != nil {
// 		log.Println(err)
// 		conn.Close()
// 		return
// 	}

// 	conn.Close()
// }

func handleConnection(conn net.Conn, port uint32) {
	// port := getRemotePort(conn)

	var (
	// tmpPort uint32
	// indx    uint32 = 0
	)
	var (
		tmpPort = Vaccant_port{}
		indx    = -1
	)

	for i := 0; i < len(runningPorts); i++ {

		if err := objs.VaccantPorts.Lookup(uint32(i), &tmpPort); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		if tmpPort.Port == port {
			indx = i
			log.Printf("Vacant_ports %T, port at index 0: %v", objs.VaccantPorts, tmpPort)
			break
		}
	}

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

	// readMongoDBMessage(conn)

	reader := bufio.NewReader(conn)

	// req, err := http.ReadRequest(reader)
	// if err != nil {
	// 	log.Printf("Error writing response: %v", err)
	// }
	for {
		tmpByte := make([]byte, 10000)
		n, err := reader.Read(tmpByte)
		fmt.Printf("Received message: length: %v,  %v\n", n, tmpByte)

		// line, err := reader.ReadString('\n')

		var message bson.Raw
		err = bson.Unmarshal(tmpByte[:n], &message)
		if err != nil {
			log.Println(err)
			conn.Close()
			return
		}

		// Extract the message data
		messageType := message[0]
		messageData := message[1:]

		// Convert the message data to a UTF-8 encoded string
		var messageString string
		switch messageType {
		case 0x01: // reply
			var reply bson.M
			err := bson.Unmarshal(messageData, &reply)
			if err != nil {
				log.Println(err)
				conn.Close()
				return
			}
			messageBytes, err := json.Marshal(reply)
			if err != nil {
				log.Println(err)
				conn.Close()
				return
			}
			messageString = string(messageBytes)
		default:
			messageString = string(messageData)
		}
		fmt.Printf("Received message: length: %v,  %v\n", n, messageString)

		// if err == io.EOF {
		if n == 0 {
			log.Printf("Error reading from connection: %v", err)
			break
		}
		if err != nil {
			log.Printf("Error reading from connection: %v", err)
			break
		}
		// fmt.Printf("Received message: %s\n", line)

		// if line == "\r\n" {
		// 	break
		// }

	}

	_, err := conn.Write([]byte(response))
	if err != nil {
		log.Printf("Error writing response: %v", err)
	}

	tmpPort.Occupied = 0
	tmpPort.Dest_ip = 0
	tmpPort.Dest_port = 0
	err = objs.VaccantPorts.Update(uint32(indx), tmpPort, // Occupied: false,
		ebpf.UpdateLock)
	if err != nil {
		log.Printf("error updating the vaccan_port: %v", err)
	}
}

func getRemotePort(conn net.Conn) int {
	addr := conn.RemoteAddr().(*net.TCPAddr)
	return addr.Port
}

// func readMongoDBMessage(conn net.Conn) (bsoncore.Document, error) {
// 	// read the message header (16 bytes)
// 	header := make([]byte, 16)
// 	if _, err := io.ReadFull(conn, header); err != nil {
// 		return nil, err
// 	}

// 	// parse the message length and request ID from the header
// 	length := int32(header[0]) | int32(header[1])<<8 | int32(header[2])<<16 | int32(header[3])<<24
// 	requestId := int32(header[8]) | int32(header[9])<<8 | int32(header[10])<<16 | int32(header[11])<<24

// 	// read the rest of the message into a buffer
// 	buffer := make([]byte, length-16)
// 	if _, err := io.ReadFull(conn, buffer); err != nil {
// 		return nil, err
// 	}

// 	// concatenate the header and buffer into a single byte slice
// 	messageBytes := bytes.Join([][]byte{header, buffer}, []byte{})

// 	// parse the message using the bsoncore package
// 	message, _, ok := bsoncore.ReadDocument(messageBytes)
// 	if ok {
// 		log.Println("unable to read empty mongo docs")
// 	}

// 	log.Printf("Recieved mongo message: requestId: %v length: %v message: %v", requestId, length, messageBytes)
// 	return message, nil
// }
