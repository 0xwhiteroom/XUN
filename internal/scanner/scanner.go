package scanner

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

var Top100 = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
	143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
	8443, 8888, 8000, 8008, 8081, 8082, 8090, 9000, 9090, 9200,
	9443, 10000, 27017, 6379, 5432, 1433, 2181, 2375, 2376, 4443,
	5000, 5432, 5601, 6443, 7001, 8083, 8089, 8181, 8500, 8983,
	9001, 9092, 9300, 11211, 15672, 28017, 50000, 161, 389, 636,
	873, 1080, 1194, 2049, 2082, 2083, 2086, 2087, 2095, 2096,
	3000, 3128, 4000, 4040, 4848, 5800, 5985, 6000, 7000, 7070,
	7080, 7443, 7474, 8020, 8025, 8088, 8800, 9418, 9999, 10443,
	1433, 1521, 3306, 5432, 6379, 9200, 27017, 50000, 8161, 61616,
}

var Top1000 []int

func init() {
	seen := map[int]bool{}
	for _, p := range Top100 {
		seen[p] = true
	}
	for p := 1; p <= 1024; p++ {
		if !seen[p] {
			Top1000 = append(Top1000, p)
			seen[p] = true
		}
	}
	extras := []int{
		1433, 1521, 2049, 2082, 2083, 2086, 2087, 2095, 2096,
		2181, 2375, 2376, 3000, 3128, 3306, 3389, 4000, 4040,
		4443, 4848, 5000, 5432, 5601, 5800, 5900, 5985, 6000,
		6379, 6443, 7001, 7080, 7443, 7474, 8000, 8008, 8020,
		8025, 8080, 8081, 8082, 8083, 8088, 8089, 8090, 8181,
		8443, 8500, 8800, 8888, 8983, 9000, 9001, 9090, 9092,
		9200, 9300, 9418, 9443, 9999, 10000, 10443, 11211, 15672,
		27017, 28017, 50000,
	}
	for _, p := range extras {
		if !seen[p] {
			Top1000 = append(Top1000, p)
			seen[p] = true
		}
	}
	sort.Ints(Top1000)
}

type Result struct {
	Host    string
	Port    int
	Proto   string
	Service string
}

func ScanTCP(hosts []string, ports []int, timeout time.Duration, threads int, progress func(done, total int64)) []Result {
	type job struct {
		host string
		port int
	}
	jobs  := make(chan job, len(hosts)*len(ports))
	out   := make(chan Result, len(hosts)*len(ports))
	total := int64(len(hosts) * len(ports))
	var done int64
	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				addr := fmt.Sprintf("%s:%d", j.host, j.port)
				conn, err := net.DialTimeout("tcp", addr, timeout)
				n := atomic.AddInt64(&done, 1)
				if progress != nil {
					progress(n, total)
				}
				if err != nil {
					continue
				}
				conn.Close()
				out <- Result{Host: j.host, Port: j.port, Proto: "tcp", Service: KnownService(j.port)}
			}
		}()
	}
	for _, h := range hosts {
		for _, p := range ports {
			jobs <- job{h, p}
		}
	}
	close(jobs)
	go func() { wg.Wait(); close(out) }()

	var results []Result
	for r := range out {
		results = append(results, r)
	}
	return results
}

func ScanUDP(hosts []string, timeout time.Duration, threads int) []Result {
	udpPorts := []int{53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1194, 1900, 4500, 5353}
	type job struct {
		host string
		port int
	}
	jobs := make(chan job, len(hosts)*len(udpPorts))
	out  := make(chan Result, len(hosts)*len(udpPorts))
	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				addr := fmt.Sprintf("%s:%d", j.host, j.port)
				conn, err := net.DialTimeout("udp", addr, timeout)
				if err != nil {
					continue
				}
				conn.SetDeadline(time.Now().Add(timeout))
				conn.Write([]byte("\x00"))
				buf := make([]byte, 64)
				_, err = conn.Read(buf)
				conn.Close()
				if err == nil {
					out <- Result{Host: j.host, Port: j.port, Proto: "udp", Service: KnownService(j.port)}
				}
			}
		}()
	}
	for _, h := range hosts {
		for _, p := range udpPorts {
			jobs <- job{h, p}
		}
	}
	close(jobs)
	go func() { wg.Wait(); close(out) }()

	var results []Result
	for r := range out {
		results = append(results, r)
	}
	return results
}

func ExpandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	for ip2 := ip.Mask(ipnet.Mask); ipnet.Contains(ip2); inc(ip2) {
		ips = append(ips, ip2.String())
	}
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

var services = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	80: "http", 110: "pop3", 111: "rpc", 135: "msrpc", 139: "netbios",
	143: "imap", 389: "ldap", 443: "https", 445: "smb", 636: "ldaps",
	873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks",
	1433: "mssql", 1521: "oracle", 1723: "pptp", 2049: "nfs",
	2181: "zookeeper", 2375: "docker", 2376: "docker-tls",
	3000: "grafana", 3128: "squid", 3306: "mysql", 3389: "rdp",
	4000: "http-alt", 4443: "https-alt", 5000: "flask",
	5432: "postgresql", 5601: "kibana", 5900: "vnc",
	6379: "redis", 6443: "kubernetes", 7001: "weblogic",
	8000: "http-alt", 8080: "http-alt", 8081: "http-alt",
	8088: "hadoop", 8089: "splunk", 8443: "https-alt",
	8500: "consul", 8888: "jupyter", 8983: "solr",
	9000: "sonarqube", 9090: "prometheus", 9092: "kafka",
	9200: "elasticsearch", 9300: "elasticsearch-cluster",
	10000: "webmin", 11211: "memcached", 15672: "rabbitmq",
	27017: "mongodb", 28017: "mongodb-http", 50000: "sap",
}

func KnownService(port int) string {
	if s, ok := services[port]; ok {
		return s
	}
	return ""
}

func SortResults(results []Result) {
	sort.Slice(results, func(i, j int) bool {
		if results[i].Host != results[j].Host {
			return results[i].Host < results[j].Host
		}
		return results[i].Port < results[j].Port
	})
}
