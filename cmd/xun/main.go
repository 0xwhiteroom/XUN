package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"xun/internal/banner"
	"xun/internal/reporter"
	"xun/internal/scanner"
)

func printBanner() {
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  \033[95m\033[1m██╗  ██╗██╗   ██╗███╗   ██╗\033[0m\n")
	fmt.Fprintf(os.Stderr, "  \033[95m\033[1m╚██╗██╔╝██║   ██║████╗  ██║\033[0m\n")
	fmt.Fprintf(os.Stderr, "  \033[95m\033[1m ╚███╔╝ ██║   ██║██╔██╗ ██║\033[0m\n")
	fmt.Fprintf(os.Stderr, "  \033[95m\033[1m ██╔██╗ ██║   ██║██║╚██╗██║\033[0m\n")
	fmt.Fprintf(os.Stderr, "  \033[95m\033[1m██╔╝ ██╗╚██████╔╝██║ ╚████║\033[0m\n")
	fmt.Fprintf(os.Stderr, "  \033[95m\033[1m╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝\033[0m\n")
	fmt.Fprintf(os.Stderr, "  \033[96m\033[1m迅  XUN v1.0 — Fast Port Scanner\033[0m\n")
	fmt.Fprintf(os.Stderr, "  \033[93mby 0xWHITEROOM 「0xホワイトルーム」\033[0m\n\n")
}

func printHelp() {
	printBanner()
	fmt.Fprintf(os.Stderr, "  \033[96m\033[1mUSAGE\033[0m\n")
	fmt.Fprintf(os.Stderr, "    xun -h <target> [options]\n\n")
	fmt.Fprintf(os.Stderr, "  \033[96m\033[1mINPUT\033[0m\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-h <host>\033[0m        Single host, IP, or CIDR\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-d <domain>\033[0m      Domain — auto resolve IP + scan\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-l <file>\033[0m        File of hosts (one per line)\n\n")
	fmt.Fprintf(os.Stderr, "  \033[96m\033[1mSCAN\033[0m\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-p <ports>\033[0m       Ports: 80,443 or 1-1000\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-top100\033[0m          Top 100 common ports (default)\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-top1000\033[0m         Top 1000 common ports\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-all\033[0m             All 65535 ports\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-udp\033[0m             UDP scan\n\n")
	fmt.Fprintf(os.Stderr, "  \033[96m\033[1mFEATURES\033[0m\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-banner\033[0m          Banner grab + version detect\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-nmap\033[0m            Auto nmap handoff\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-nmap-flags\033[0m      Custom nmap flags (default: -sV -sC)\n\n")
	fmt.Fprintf(os.Stderr, "  \033[96m\033[1mCONFIG\033[0m\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-c <int>\033[0m         Threads (default 1000)\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-timeout <ms>\033[0m    Timeout ms (default 500)\n\n")
	fmt.Fprintf(os.Stderr, "  \033[96m\033[1mOUTPUT\033[0m\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-o <file>\033[0m        Save TXT\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-oj <file>\033[0m       Save JSON\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-ojl <file>\033[0m      Save JSONL\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-silent\033[0m          host:port only to stdout\n\n")
	fmt.Fprintf(os.Stderr, "  \033[92m\033[1mEXAMPLES\033[0m\n")
	fmt.Fprintf(os.Stderr, "    \033[92mxun -h 192.168.1.1\033[0m\n")
	fmt.Fprintf(os.Stderr, "    \033[92mxun -d example.com\033[0m\n")
	fmt.Fprintf(os.Stderr, "    \033[92mxun -d example.com -top1000 -banner\033[0m\n")
	fmt.Fprintf(os.Stderr, "    \033[92mxun -h 192.168.1.1 -top1000 -banner\033[0m\n")
	fmt.Fprintf(os.Stderr, "    \033[92mxun -h 192.168.1.0/24 -top100\033[0m\n")
	fmt.Fprintf(os.Stderr, "    \033[92mxun -h target.com -all -nmap\033[0m\n")
	fmt.Fprintf(os.Stderr, "    \033[92mxun -l hosts.txt -top100 -silent >> ports.txt\033[0m\n\n")
}

func main() {
	h         := flag.String("h",          "",      "")
	d         := flag.String("d",          "",      "")
	l         := flag.String("l",          "",      "")
	ports     := flag.String("p",          "",      "")
	top100    := flag.Bool("top100",       false,   "")
	top1000   := flag.Bool("top1000",      false,   "")
	scanAll   := flag.Bool("all",          false,   "")
	doUDP     := flag.Bool("udp",          false,   "")
	doBanner  := flag.Bool("banner",       false,   "")
	doNmap    := flag.Bool("nmap",         false,   "")
	nmapFlags := flag.String("nmap-flags", "-sV -sC", "")
	c         := flag.Int("c",             1000,    "")
	timeoutMs := flag.Int("timeout",       500,     "")
	outTXT    := flag.String("o",          "",      "")
	outJSON   := flag.String("oj",         "",      "")
	outJSONL  := flag.String("ojl",        "",      "")
	silent    := flag.Bool("silent",       false,   "")
	version   := flag.Bool("version",      false,   "")

	flag.Usage = printHelp
	flag.Parse()

	if *version {
		fmt.Fprintln(os.Stderr, "xun 迅 v1.0  by FIN 「サイバー守護者」")
		os.Exit(0)
	}
	if *h == "" && *l == "" && *d == "" {
		printHelp()
		os.Exit(0)
	}
	if !*silent {
		printBanner()
	}

	// Domain resolve
	domainMap := map[string][]string{} // ip -> []domain names
	if *d != "" {
		domain := strings.TrimSpace(*d)
		domain  = strings.TrimPrefix(domain, "https://")
		domain  = strings.TrimPrefix(domain, "http://")
		domain  = strings.Split(domain, "/")[0]
		if !*silent {
			fmt.Fprintf(os.Stderr, "  \033[96m[*]\033[0m Resolving \033[1m%s\033[0m...\n", domain)
		}
		ips, err := net.LookupHost(domain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  \033[91m[-]\033[0m Cannot resolve %s: %s\n", domain, err)
			os.Exit(1)
		}
		if !*silent {
			for _, ip := range ips {
				fmt.Fprintf(os.Stderr, "  \033[92m[+]\033[0m \033[1m%s\033[0m → \033[93m%s\033[0m\n", domain, ip)
			}
			fmt.Fprintf(os.Stderr, "\n")
		}
		for _, ip := range ips {
			domainMap[ip] = append(domainMap[ip], domain)
		}
	}

	// Collect hosts
	var hosts []string
	addHost := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "#") { return }
		if strings.Contains(raw, "/") {
			ips, err := scanner.ExpandCIDR(raw)
			if err != nil {
				fmt.Fprintf(os.Stderr, "\033[91m[-]\033[0m bad CIDR %s: %s\n", raw, err)
				return
			}
			hosts = append(hosts, ips...)
		} else {
			hosts = append(hosts, raw)
		}
	}
	if *h != "" { addHost(*h) }
	for ip := range domainMap { hosts = append(hosts, ip) }
	if *l != "" {
		f, err := os.Open(*l)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\033[91m[-]\033[0m cannot open: %s\n", err)
			os.Exit(1)
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			addHost(sc.Text())
		}
		f.Close()
	}
	if len(hosts) == 0 {
		fmt.Fprintln(os.Stderr, "\033[91m[-]\033[0m no valid hosts")
		os.Exit(1)
	}

	// Port list
	var portList []int
	switch {
	case *ports != "":
		portList = parsePorts(*ports)
	case *scanAll:
		portList = makeRange(1, 65535)
	case *top1000:
		portList = scanner.Top1000
	case *top100:
		portList = scanner.Top100
	default:
		portList = scanner.Top100
	}
	if len(portList) == 0 {
		fmt.Fprintln(os.Stderr, "\033[91m[-]\033[0m no valid ports")
		os.Exit(1)
	}

	timeout := time.Duration(*timeoutMs) * time.Millisecond

	if !*silent {
		fmt.Fprintf(os.Stderr, "  \033[96m[*]\033[0m Scanning \033[1m%d\033[0m host(s)  \033[1m%d\033[0m port(s)  threads:\033[1m%d\033[0m  timeout:\033[1m%dms\033[0m\n\n",
			len(hosts), len(portList), *c, *timeoutMs)
	}

	rep, err := reporter.New(*outJSON, *outTXT, *outJSONL, *silent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\033[91m[-]\033[0m output error: %s\n", err)
		os.Exit(1)
	}
	defer rep.Close()

	// Progress bar
	total := int64(len(hosts) * len(portList))
	progress := func(done, tot int64) {
		if *silent { return }
		pct    := float64(done) / float64(tot) * 100
		bar    := int(pct / 5)
		filled := strings.Repeat("█", bar)
		empty  := strings.Repeat("░", 20-bar)
		fmt.Fprintf(os.Stderr, "\r  \033[96m[%s%s]\033[0m  %.0f%%  (%d/%d)  ", filled, empty, pct, done, tot)
	}
	_ = total

	// TCP Scan
	tcpResults := scanner.ScanTCP(hosts, portList, timeout, *c, progress)
	if !*silent { fmt.Fprintf(os.Stderr, "\n") }
	scanner.SortResults(tcpResults)

	lastHost := ""
	for _, r := range tcpResults {
		if r.Host != lastHost {
			// Show domain name if this IP came from -d resolve
		headerLabel := r.Host
		if domains, ok := domainMap[r.Host]; ok {
			headerLabel = strings.Join(domains, ", ") + " (" + r.Host + ")"
		}
		rep.PrintHeader(headerLabel)
			lastHost = r.Host
		}
		e := reporter.Entry{
			Host:    r.Host,
			Port:    r.Port,
			Proto:   "tcp",
			Service: r.Service,
		}
		if *doBanner {
			bi := banner.Grab(r.Host, r.Port, timeout*4)
			e.Banner  = bi.Banner
			e.Version = bi.Version
			e.Extra   = bi.Extra
		}
		rep.Add(e)
	}

	// UDP
	if *doUDP {
		if !*silent { fmt.Fprintf(os.Stderr, "\n  \033[96m[*]\033[0m UDP scan...\n") }
		udpResults := scanner.ScanUDP(hosts, timeout*2, *c/2)
		scanner.SortResults(udpResults)
		for _, r := range udpResults {
			rep.Add(reporter.Entry{Host: r.Host, Port: r.Port, Proto: "udp", Service: r.Service})
		}
	}

	// Nmap handoff
	nmapCmd := ""
	if *doNmap {
		open := rep.OpenPorts()
		if len(open) > 0 {
			seen := map[int]bool{}
			var pnums []string
			for _, e := range open {
				if !seen[e.Port] {
					seen[e.Port] = true
					pnums = append(pnums, strconv.Itoa(e.Port))
				}
			}
			nmapCmd = fmt.Sprintf("nmap %s -p %s %s", *nmapFlags, strings.Join(pnums, ","), strings.Join(hosts, " "))
		}
	}

	if *outJSON != "" {
		if err := rep.SaveJSON(*outJSON); err != nil {
			fmt.Fprintf(os.Stderr, "\033[91m[-]\033[0m JSON save: %s\n", err)
		} else if !*silent {
			fmt.Fprintf(os.Stderr, "  \033[92m[+]\033[0m Saved → %s\n", *outJSON)
		}
	}
	rep.Summary(nmapCmd)

	if *doNmap && nmapCmd != "" {
		fmt.Fprintf(os.Stderr, "\n  \033[93m\033[1m[→]\033[0m Run nmap:\n  \033[93m%s\033[0m\n\n", nmapCmd)
	}
}

func parsePorts(s string) []int {
	seen := map[int]bool{}
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, e1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			hi, e2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if e1 != nil || e2 != nil || lo < 1 || hi > 65535 { continue }
			for p := lo; p <= hi; p++ {
				if !seen[p] { seen[p] = true; out = append(out, p) }
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 { continue }
			if !seen[p] { seen[p] = true; out = append(out, p) }
		}
	}
	return out
}

func makeRange(lo, hi int) []int {
	out := make([]int, hi-lo+1)
	for i := range out { out[i] = lo + i }
	return out
}
