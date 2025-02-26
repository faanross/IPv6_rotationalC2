package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"regexp"
	"time"
)

//go:embed config.json
var configFS embed.FS

// Config holds all the configuration values loaded from config.json
type Config struct {
	ServerIPs       []string `json:"serverIPs"`
	Port            int      `json:"port"`
	Sleep           int      `json:"sleep"`
	Jitter          int      `json:"jitter"`
	DataJitter      int      `json:"data_jitter"`
	RotationCounter int      `json:"rotation_counter"`
}

// loadConfig loads the configuration from the embedded config.json
func loadConfig() (*Config, error) {
	// Read the embedded config file
	data, err := configFS.ReadFile("config.json")
	if err != nil {
		return nil, fmt.Errorf("could not read embedded config.json: %v", err)
	}

	// Parse the config
	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("error parsing config.json: %v", err)
	}

	// Validate IPv6 addresses
	ipv6Regex := regexp.MustCompile(`^\[[:0-9a-fA-F]+\]$`)
	for _, ip := range config.ServerIPs {
		if !ipv6Regex.MatchString(ip) {
			return nil, fmt.Errorf("invalid IPv6 address format: %s", ip)
		}
	}

	// Ensure we have at least one server IP
	if len(config.ServerIPs) == 0 {
		return nil, fmt.Errorf("at least one IPv6 address must be specified in serverIPs")
	}

	// Ensure rotation counter is a positive number
	if config.RotationCounter <= 0 {
		return nil, fmt.Errorf("rotation_counter must be a positive integer")
	}

	return &config, nil
}

func main() {
	// Initialize random number generator
	rand.Seed(time.Now().UnixNano())

	// Load configuration
	config, err := loadConfig()
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Create custom transport and client to handle IPv6 link-local addresses
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).DialContext,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   2 * time.Second,
	}

	// Randomly select initial IP address index
	currentIPIdx := rand.Intn(len(config.ServerIPs))
	// Initialize the counter for IP rotation
	remainingConnections := config.RotationCounter

	for {
		ip := config.ServerIPs[currentIPIdx]
		fmt.Printf("Trying to connect to %s (remaining connections before rotation: %d)\n",
			ip, remainingConnections)

		makeRequest(client, ip, config.Port, config.DataJitter)

		// Decrement the rotation counter
		remainingConnections--

		// Check if we need to select a new IP
		if remainingConnections <= 0 {
			// Reset counter and select new random IP
			remainingConnections = config.RotationCounter

			// Select a new random IP (make sure it's different from the current one)
			if len(config.ServerIPs) > 1 {
				// Get a new random index that is different from the current one
				newIPIdx := currentIPIdx
				for newIPIdx == currentIPIdx {
					newIPIdx = rand.Intn(len(config.ServerIPs))
				}
				currentIPIdx = newIPIdx
			} else {
				// If there's only one IP, we just stick with it
				currentIPIdx = 0
			}

			fmt.Printf("Rotation counter reached zero. Selected new IP: %s\n",
				config.ServerIPs[currentIPIdx])
		}

		// Wait with configured sleep and jitter
		sleepTime := float64(config.Sleep) + rand.Float64()*float64(config.Jitter)
		time.Sleep(time.Duration(sleepTime) * time.Second)
	}
}

func makeRequest(client *http.Client, ip string, port int, dataJitter int) {
	url := fmt.Sprintf("http://%s:%d", ip, port)

	// Generate random sized data
	randomData := generateRandomData(dataJitter)

	// Create POST request with random data
	req, err := http.NewRequest("POST", url, bytes.NewReader(randomData))
	if err != nil {
		fmt.Printf("Failed to create request to %s: %v\n", ip, err)
		return
	}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Request failed to %s: %v\n", ip, err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("[%s] Connected successfully to %s with %d bytes of data\n",
		time.Now().Format("15:04:05"), ip, len(randomData))
}

func generateRandomData(maxSize int) []byte {
	size := rand.Intn(maxSize + 1) // Intn(maxSize+1) gives 0-maxSize inclusive
	data := make([]byte, size)
	rand.Read(data)
	return data
}
