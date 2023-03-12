package main

import (
	"fmt"
	"net"
	"time"
)

func runTest(host string, port int) time.Duration {
	start := time.Now()

	// Connect to the TCP server
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Send a test message
	message := "Hello, world!"
	_, err = conn.Write([]byte(message))
	if err != nil {
		panic(err)
	}

	// Read the response
	buffer := make([]byte, 1024)
	_, err = conn.Read(buffer)
	if err != nil {
		panic(err)
	}

	elapsed := time.Since(start)
	return elapsed
}
func main() {
	// Set up the test parameters
	host := "127.0.0.1"
	port := 48620
	numTests := 1

	// Run the tests and record the latencies
	latencies := make([]time.Duration, numTests)
	start := time.Now()
	for i := 0; i < numTests; i++ {
		latency := runTest(host, port)
		latencies[i] = latency
		time.Sleep(time.Millisecond * 10)
	}
	elapsed := time.Since(start)

	// Calculate the average latency and requests per second
	totalLatency := time.Duration(0)
	for _, latency := range latencies {
		totalLatency += latency
	}
	averageLatency := totalLatency / time.Duration(numTests)
	requestsPerSecond := float64(numTests) / elapsed.Seconds()

	fmt.Printf("Average latency: %v\n", averageLatency)
	fmt.Printf("Requests per second: %.2f\n", requestsPerSecond)
}
