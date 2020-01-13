package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
)

func main() {
	hostnamePtr := flag.String("hostname", "", "Target Redis ip-address (Required)")
	portPtr := flag.String("port", "", "Target Redis port (Required)")
	passwordPtr := flag.String("password", "", "Target Redis `masterauth` password.")
	cacertPtr := flag.String("cacert", "", "Path to certificate")

	flag.Parse()

	if len(os.Args) < 2 {
		fmt.Printf(
			`Redis Proxy
==============
password:   Password to target redis server. ( Not needed if both target and source share the same password. )
hostname:   Hostname of the target redis server.
port:       Port of the target redis server.
cacert:     Path to the ca certificate.
`)
		os.Exit(1)
	}

	if *hostnamePtr == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *portPtr == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	var err error
	var tlsConfig = &tls.Config{}

	if *cacertPtr != "" {
		tlsConfig, err = buildCertificate(*cacertPtr)
		if err != nil {
			panic(err)
		}
	}

	listener, err := listenerInterface("5000")
	if err != nil {
		log.Fatalf("Failed to setup server: %s", err)
	}

	log.Printf("Replication is now available on port `5000`")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalf("Failed accepting connection: %s", err)
		}

		// Each client connection will be paired with separate server connection.
		targetURI := fmt.Sprintf("%s:%s", *hostnamePtr, *portPtr)
		log.Println(targetURI)
		server, err := tls.Dial("tcp", targetURI, tlsConfig)
		if err != nil {
			log.Fatalf("client: dial: %s", err)
		}

		defer server.Close()

		// Authenticates with the remote redis using the specifed password.
		// If used for replication, the incoming Redis will use `masterauth`.
		// This isolation allows Redis clusters to sync with each other who
		// may have different `masterauth` passwords configured.
		if *passwordPtr != "" {
			if err = authenticate(server, *passwordPtr); err != nil {
				log.Fatalf("failed to authenticate: %s", err.Error())
			}
		}

		go handleConn(conn, server)
	}
}

func handleConn(client, server net.Conn) {
	// Client <-> Server Communications
	go func(client, server net.Conn) { communicate(client, server) }(client, server)

	// Server <-> Client Communications
	go func(client, server net.Conn) { communicate(server, client) }(client, server)

	log.Printf("Established connection between %s <-> %s", client.RemoteAddr(), server.RemoteAddr())
}

func communicate(source, target net.Conn) {
	reader := bufio.NewReader(source)
	for {
		reply, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("Error reading from %s. Error: %s", source.RemoteAddr(), err.Error())
		}
		io.WriteString(target, string(reply))
	}
	log.Printf("lost connection with %s... Attempting to reconnect", source.RemoteAddr())
}

func listenerInterface(port string) (*net.TCPListener, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf(":%s", port))
	if err != nil {
		return nil, errors.New("Failed to resolve tcp addr")
	}
	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return nil, errors.New("Failed to listen to tcp")
	}
	return listener, nil
}

func buildCertificate(pathToCert string) (*tls.Config, error) {
	clientCert, err := ioutil.ReadFile(pathToCert)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(clientCert))
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %s" + err.Error())
	}

	cert := tls.Certificate{Leaf: leaf}

	return &tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}, nil
}

func authenticate(conn net.Conn, password string) error {
	message := fmt.Sprintf("AUTH %s\n", password)
	_, err := io.WriteString(conn, message)
	if err != nil {
		return err
	}

	reply := make([]byte, 256)
	conn.Read(reply)
	if !strings.Contains(string(reply), "+OK") {
		return err
	}

	return nil
}