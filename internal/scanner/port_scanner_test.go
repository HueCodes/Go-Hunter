package scanner

import (
	"context"
	"log/slog"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestParsePorts_SinglePort(t *testing.T) {
	ports, err := ParsePorts("80")
	require.NoError(t, err)
	assert.Equal(t, []int{80}, ports)
}

func TestParsePorts_MultiplePorts(t *testing.T) {
	ports, err := ParsePorts("80,443,8080")
	require.NoError(t, err)
	assert.Equal(t, []int{80, 443, 8080}, ports)
}

func TestParsePorts_Range(t *testing.T) {
	ports, err := ParsePorts("1000-1005")
	require.NoError(t, err)
	assert.Equal(t, []int{1000, 1001, 1002, 1003, 1004, 1005}, ports)
}

func TestParsePorts_MixedFormat(t *testing.T) {
	ports, err := ParsePorts("80,443,1000-1003")
	require.NoError(t, err)
	assert.Equal(t, []int{80, 443, 1000, 1001, 1002, 1003}, ports)
}

func TestParsePorts_Deduplication(t *testing.T) {
	ports, err := ParsePorts("80,80,443,80")
	require.NoError(t, err)
	assert.Equal(t, []int{80, 443}, ports)
}

func TestParsePorts_EmptyReturnsDefaults(t *testing.T) {
	ports, err := ParsePorts("")
	require.NoError(t, err)
	assert.NotEmpty(t, ports)
	assert.Contains(t, ports, 80)
	assert.Contains(t, ports, 443)
	assert.Contains(t, ports, 22)
}

func TestParsePorts_InvalidRange(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"reversed range", "1000-500"},
		{"port too high", "80,70000"},
		{"port too low", "0"},
		{"negative port", "-1"},
		{"invalid number", "abc"},
		{"incomplete range", "1000-"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePorts(tt.input)
			assert.Error(t, err)
		})
	}
}

func TestParsePorts_WhitespaceHandling(t *testing.T) {
	ports, err := ParsePorts("  80 , 443 , 8080  ")
	require.NoError(t, err)
	assert.Equal(t, []int{80, 443, 8080}, ports)
}

func TestPortScanner_ScanHost_OpenPort(t *testing.T) {
	// Start a local TCP listener to simulate an open port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	// Get the port we're listening on
	addr := listener.Addr().(*net.TCPAddr)
	port := addr.Port

	// Accept connections in background
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("SSH-2.0-OpenSSH_8.0\r\n"))
			conn.Close()
		}
	}()

	scanner := NewPortScanner(newTestLogger(), &PortScanConfig{
		Timeout:     2 * time.Second,
		Concurrency: 10,
	})

	ctx := context.Background()
	results := scanner.ScanHost(ctx, "127.0.0.1", []int{port})

	require.Len(t, results, 1)
	assert.Equal(t, port, results[0].Port)
	assert.True(t, results[0].Open)
	assert.Equal(t, "tcp", results[0].Protocol)
	assert.Contains(t, results[0].Banner, "SSH")
	assert.Equal(t, "ssh", results[0].Service)
}

func TestPortScanner_ScanHost_ClosedPort(t *testing.T) {
	// Find a port that's definitely not listening
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().(*net.TCPAddr)
	port := addr.Port
	listener.Close() // Close immediately so port is not listening

	scanner := NewPortScanner(newTestLogger(), &PortScanConfig{
		Timeout:     500 * time.Millisecond,
		Concurrency: 10,
	})

	ctx := context.Background()
	results := scanner.ScanHost(ctx, "127.0.0.1", []int{port})

	// Should return empty results for closed ports
	assert.Empty(t, results)
}

func TestPortScanner_ScanHost_Timeout(t *testing.T) {
	// Use a non-routable address to trigger timeout
	scanner := NewPortScanner(newTestLogger(), &PortScanConfig{
		Timeout:     100 * time.Millisecond,
		Concurrency: 10,
	})

	ctx := context.Background()
	start := time.Now()
	results := scanner.ScanHost(ctx, "10.255.255.1", []int{12345})
	elapsed := time.Since(start)

	// Should return empty and complete within reasonable time
	assert.Empty(t, results)
	assert.Less(t, elapsed, 2*time.Second)
}

func TestPortScanner_ScanHost_ContextCancellation(t *testing.T) {
	scanner := NewPortScanner(newTestLogger(), &PortScanConfig{
		Timeout:     5 * time.Second,
		Concurrency: 10,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	start := time.Now()
	results := scanner.ScanHost(ctx, "127.0.0.1", []int{80, 443, 8080})
	elapsed := time.Since(start)

	// Should return quickly (context already cancelled)
	assert.Less(t, elapsed, 1*time.Second)
	// Results should be empty when context is cancelled
	assert.Empty(t, results)
}

func TestPortScanner_ScanHost_Concurrency(t *testing.T) {
	// Start multiple listeners
	ports := make([]int, 5)
	listeners := make([]net.Listener, 5)

	for i := 0; i < 5; i++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		listeners[i] = listener
		ports[i] = listener.Addr().(*net.TCPAddr).Port

		go func(l net.Listener) {
			for {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				conn.Close()
			}
		}(listener)
	}
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
	}()

	scanner := NewPortScanner(newTestLogger(), &PortScanConfig{
		Timeout:     2 * time.Second,
		Concurrency: 3, // Less than number of ports to test semaphore
	})

	ctx := context.Background()
	results := scanner.ScanHost(ctx, "127.0.0.1", ports)

	// Should find all 5 open ports
	assert.Len(t, results, 5)
	for _, result := range results {
		assert.True(t, result.Open)
	}
}

func TestPortScanner_ResultsToFindings_Basic(t *testing.T) {
	scanner := NewPortScanner(newTestLogger(), nil)

	results := []PortScanResult{
		{Port: 22, Protocol: "tcp", Service: "ssh", Open: true, Banner: "SSH-2.0-OpenSSH_8.0"},
		{Port: 80, Protocol: "tcp", Service: "http", Open: true},
		{Port: 3306, Protocol: "tcp", Service: "mysql", Open: true},
	}

	assetID := uuid.New()
	scanID := uuid.New()
	orgID := uuid.New()

	findings := scanner.ResultsToFindings("192.168.1.1", results, assetID, scanID, orgID)

	require.Len(t, findings, 3)

	// Check SSH finding
	sshFinding := findings[0]
	assert.Contains(t, sshFinding.Title, "22")
	assert.Contains(t, sshFinding.Title, "ssh")
	assert.Equal(t, "open_port", sshFinding.Type)
	assert.Equal(t, "network", sshFinding.Category)
	assert.Equal(t, assetID, sshFinding.AssetID)
	assert.Equal(t, scanID, sshFinding.ScanID)
	assert.Equal(t, orgID, sshFinding.OrganizationID)
	assert.NotEmpty(t, sshFinding.Hash)
}

func TestPortScanner_ResultsToFindings_Severity(t *testing.T) {
	scanner := NewPortScanner(newTestLogger(), nil)

	tests := []struct {
		service          string
		port             int
		expectedSeverity string
	}{
		{"telnet", 23, "high"},
		{"ftp", 21, "high"},
		{"vnc", 5900, "high"},
		{"mysql", 3306, "medium"},
		{"redis", 6379, "medium"},
		{"rdp", 3389, "medium"},
		{"ssh", 22, "low"},
		{"http", 80, "low"},
		{"", 8888, "info"},
	}

	for _, tt := range tests {
		t.Run(tt.service+"-"+strconv.Itoa(tt.port), func(t *testing.T) {
			results := []PortScanResult{
				{Port: tt.port, Protocol: "tcp", Service: tt.service, Open: true},
			}

			findings := scanner.ResultsToFindings("test", results, uuid.New(), uuid.New(), uuid.New())
			require.Len(t, findings, 1)
			assert.Equal(t, tt.expectedSeverity, string(findings[0].Severity))
		})
	}
}

func TestPortScanner_ResultsToFindings_SkipsClosedPorts(t *testing.T) {
	scanner := NewPortScanner(newTestLogger(), nil)

	results := []PortScanResult{
		{Port: 22, Protocol: "tcp", Service: "ssh", Open: true},
		{Port: 80, Protocol: "tcp", Service: "http", Open: false}, // Closed
		{Port: 443, Protocol: "tcp", Service: "https", Open: true},
	}

	findings := scanner.ResultsToFindings("test", results, uuid.New(), uuid.New(), uuid.New())

	// Should only have 2 findings (skips closed port)
	assert.Len(t, findings, 2)
}

func TestPortScanner_ResultsToFindings_UniqueHashes(t *testing.T) {
	scanner := NewPortScanner(newTestLogger(), nil)
	assetID := uuid.New()

	results := []PortScanResult{
		{Port: 22, Protocol: "tcp", Service: "ssh", Open: true},
		{Port: 80, Protocol: "tcp", Service: "http", Open: true},
	}

	findings := scanner.ResultsToFindings("test", results, assetID, uuid.New(), uuid.New())

	require.Len(t, findings, 2)
	assert.NotEqual(t, findings[0].Hash, findings[1].Hash)
}

func TestPortScanner_ResultsToFindings_ConsistentHashes(t *testing.T) {
	scanner := NewPortScanner(newTestLogger(), nil)
	assetID := uuid.New()
	scanID := uuid.New()
	orgID := uuid.New()

	results := []PortScanResult{
		{Port: 22, Protocol: "tcp", Service: "ssh", Open: true},
	}

	findings1 := scanner.ResultsToFindings("test", results, assetID, scanID, orgID)
	findings2 := scanner.ResultsToFindings("test", results, assetID, scanID, orgID)

	// Same input should produce same hash
	assert.Equal(t, findings1[0].Hash, findings2[0].Hash)
}

func TestPortScanner_DefaultConfig(t *testing.T) {
	scanner := NewPortScanner(newTestLogger(), nil)
	assert.NotNil(t, scanner)
	assert.Equal(t, 3*time.Second, scanner.timeout)
	assert.Equal(t, 100, scanner.concurrency)
}

func TestPortScanner_CustomConfig(t *testing.T) {
	scanner := NewPortScanner(newTestLogger(), &PortScanConfig{
		Timeout:     5 * time.Second,
		Concurrency: 50,
	})
	assert.Equal(t, 5*time.Second, scanner.timeout)
	assert.Equal(t, 50, scanner.concurrency)
}

func TestSanitizeBanner(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"normal text", "SSH-2.0-OpenSSH", "SSH-2.0-OpenSSH"},
		{"with null bytes", "SSH\x00-2.0", "SSH-2.0"},
		{"with control chars", "SSH\x01\x02-2.0", "SSH-2.0"},
		{"with newlines", "SSH-2.0\r\nMore Info", "SSH-2.0\r\nMore Info"},
		{"long text truncated", string(make([]byte, 600)), ""}, // 600 null bytes become empty
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeBanner(tt.input)
			if tt.name == "long text truncated" {
				assert.LessOrEqual(t, len(result), 500)
			} else {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestDetectServiceFromBanner(t *testing.T) {
	tests := []struct {
		banner   string
		expected string
	}{
		{"SSH-2.0-OpenSSH_8.0", "ssh"},
		{"220 FTP Server Ready", "ftp"},
		{"220 mail.example.com ESMTP Postfix", "smtp"},
		{"HTTP/1.1 200 OK", "http"},
		{"5.7.32 MySQL Community Server", "mysql"},
		{"PostgreSQL 14.0", "postgresql"},
		{"REDIS:0.1", "redis"},
		{"MongoDB", "mongodb"},
		{"Elasticsearch", "elasticsearch"},
		{"Unknown Banner", ""},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := detectServiceFromBanner(tt.banner)
			assert.Equal(t, tt.expected, result)
		})
	}
}
