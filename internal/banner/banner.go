package banner

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type Info struct {
	Banner  string
	Version string
	Extra   string
}

func Grab(host string, port int, timeout time.Duration) *Info {
	info := &Info{}
	switch port {
	case 80, 8080, 8000, 8008, 8081, 8082, 8083, 8090, 8181, 8888, 9000, 3000, 4000:
		grabHTTP(host, port, false, info, timeout)
	case 443, 8443, 4443, 9443, 10443, 2083, 2087, 2096:
		grabHTTP(host, port, true, info, timeout)
	case 22:
		grabGeneric(host, port, info, timeout)
	case 21:
		grabGeneric(host, port, info, timeout)
	case 25, 587:
		grabGeneric(host, port, info, timeout)
	case 3306:
		grabMySQL(host, port, info, timeout)
	case 6379:
		grabRedis(host, port, info, timeout)
	default:
		grabGeneric(host, port, info, timeout)
	}
	return info
}

func grabHTTP(host string, port int, useTLS bool, info *Info, timeout time.Duration) {
	var conn net.Conn
	var err error
	addr := fmt.Sprintf("%s:%d", host, port)
	if useTLS {
		conn, err = tls.DialWithDialer(
			&net.Dialer{Timeout: timeout}, "tcp", addr,
			&tls.Config{InsecureSkipVerify: true},
		)
	} else {
		conn, err = net.DialTimeout("tcp", addr, timeout)
	}
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	req := fmt.Sprintf("HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: XUN/1.0\r\n\r\n", host)
	conn.Write([]byte(req))
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		low := strings.ToLower(line)
		if strings.HasPrefix(low, "http/") {
			parts := strings.SplitN(line, " ", 3)
			if len(parts) >= 2 {
				info.Banner = "HTTP " + parts[1]
			}
		}
		if strings.HasPrefix(low, "server:") {
			info.Version = strings.TrimSpace(line[7:])
		}
	}
	if useTLS {
		info.Banner = strings.Replace(info.Banner, "HTTP", "HTTPS", 1)
	}
}

func grabMySQL(host string, port int, info *Info, timeout time.Duration) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 5 {
		return
	}
	data := buf[5:n]
	end := 0
	for end < len(data) && data[end] != 0 {
		end++
	}
	if end > 0 {
		info.Banner  = "MySQL"
		info.Version = string(data[:end])
	}
}

func grabRedis(host string, port int, info *Info, timeout time.Duration) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	conn.Write([]byte("INFO server\r\n"))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}
	resp := string(buf[:n])
	info.Banner = "Redis"
	for _, line := range strings.Split(resp, "\n") {
		if strings.HasPrefix(line, "redis_version:") {
			info.Version = strings.TrimSpace(strings.TrimPrefix(line, "redis_version:"))
		}
	}
	if strings.Contains(resp, "redis_version") {
		info.Extra = "NO AUTH"
	}
}

func grabGeneric(host string, port int, info *Info, timeout time.Duration) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}
	raw := strings.TrimSpace(string(buf[:n]))
	var clean []rune
	for _, r := range raw {
		if r >= 32 && r < 127 {
			clean = append(clean, r)
		}
	}
	if len(clean) > 0 {
		s := string(clean)
		if len(s) > 60 {
			s = s[:57] + "..."
		}
		info.Banner = s
		// Try to extract version
		parts := strings.Fields(s)
		for _, p := range parts {
			if len(p) > 2 && (p[0] >= '0' && p[0] <= '9') {
				info.Version = p
				break
			}
		}
	}
}

// needed for HTTP client fallback
var _ = http.StatusOK
var _ = io.EOF
