package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type Entry struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
	Version string `json:"version,omitempty"`
	Extra   string `json:"extra,omitempty"`
}

type Reporter struct {
	mu      sync.Mutex
	entries []Entry
	start   time.Time
	fJSON   *os.File
	fTXT    *os.File
	fJSONL  *os.File
	silent  bool
	lastHost string
}

func New(jsonOut, txtOut, jsonlOut string, silent bool) (*Reporter, error) {
	r := &Reporter{start: time.Now(), silent: silent}
	open := func(p string) (*os.File, error) {
		if p == "" {
			return nil, nil
		}
		return os.Create(p)
	}
	var err error
	if r.fJSON,  err = open(jsonOut);  err != nil { return nil, err }
	if r.fTXT,   err = open(txtOut);   err != nil { return nil, err }
	if r.fJSONL, err = open(jsonlOut); err != nil { return nil, err }
	return r, nil
}

func (rep *Reporter) Close() {
	for _, f := range []*os.File{rep.fJSON, rep.fTXT, rep.fJSONL} {
		if f != nil {
			f.Close()
		}
	}
}

func (rep *Reporter) PrintHeader(host string) {
	if rep.silent {
		return
	}
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  \033[93m\033[1mScan report for %s\033[0m\n", host)
	fmt.Fprintf(os.Stderr, "  \033[2m%-16s  %-8s  %-14s  %s\033[0m\n", "PORT", "STATE", "SERVICE", "VERSION")
	fmt.Fprintf(os.Stderr, "  \033[2m%s\033[0m\n", strings.Repeat("─", 60))
}

func (rep *Reporter) Add(e Entry) {
	rep.mu.Lock()
	defer rep.mu.Unlock()
	rep.entries = append(rep.entries, e)

	// stdout — machine readable, >> works
	fmt.Printf("%s:%d\n", e.Host, e.Port)

	if rep.silent {
		return
	}

	portCol := fmt.Sprintf("%d/%s", e.Port, e.Proto)
	svc     := strings.ToLower(e.Service)
	if svc  == "" { svc = "unknown" }

	version := e.Version
	if version == "" { version = e.Banner }
	if len(version) > 35 { version = version[:32] + "..." }

	extra := ""
	if e.Extra != "" {
		extra = fmt.Sprintf("  \033[91m\033[1m⚠ %s\033[0m", e.Extra)
	}

	fmt.Fprintf(os.Stderr, "  \033[92m\033[1m%-16s\033[0m  \033[92mopen\033[0m    \033[96m%-14s\033[0m  \033[97m%-35s\033[0m%s\n",
		portCol, svc, version, extra)

	if rep.fTXT != nil {
		line := fmt.Sprintf("%-16s  open    %-14s  %s", portCol, svc, version)
		if e.Extra != "" { line += "  " + e.Extra }
		fmt.Fprintln(rep.fTXT, line)
	}
	if rep.fJSONL != nil {
		b, _ := json.Marshal(e)
		fmt.Fprintln(rep.fJSONL, string(b))
	}
}

func (rep *Reporter) Summary(nmapCmd string) {
	rep.mu.Lock()
	defer rep.mu.Unlock()
	if rep.silent {
		return
	}
	elapsed := time.Since(rep.start)
	div     := strings.Repeat("─", 60)
	fmt.Fprintf(os.Stderr, "\n  \033[2m%s\033[0m\n", div)
	fmt.Fprintf(os.Stderr, "  \033[92m\033[1m[✓]\033[0m  \033[1m%d open port(s)\033[0m  scanned in \033[2m%.2fs\033[0m\n",
		len(rep.entries), elapsed.Seconds())
	if nmapCmd != "" {
		fmt.Fprintf(os.Stderr, "\n  \033[93m\033[1m[→ nmap]\033[0m\n  \033[93m%s\033[0m\n", nmapCmd)
	}
	fmt.Fprintf(os.Stderr, "  \033[2m%s\033[0m\n\n", div)
}

func (rep *Reporter) SaveJSON(path string) error {
	rep.mu.Lock()
	defer rep.mu.Unlock()
	f, err := os.Create(path)
	if err != nil { return err }
	defer f.Close()
	b, _ := json.MarshalIndent(rep.entries, "", "  ")
	_, err = f.Write(b)
	return err
}

func (rep *Reporter) OpenPorts() []Entry {
	rep.mu.Lock()
	defer rep.mu.Unlock()
	out := make([]Entry, len(rep.entries))
	copy(out, rep.entries)
	return out
}
