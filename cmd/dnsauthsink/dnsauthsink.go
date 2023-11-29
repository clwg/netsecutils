package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
)

var (
	defaultAnswer       string
	listenAddress       string // Variable for listening address
	db                  *sql.DB
	useSourceIPAsAnswer bool // Flag to use source IP as the answer
)

func main() {
	flag.StringVar(&defaultAnswer, "default-answer", "127.0.0.1", "Default answer for DNS queries")
	flag.StringVar(&listenAddress, "listen", ":53", "The address to listen on for DNS queries")
	flag.BoolVar(&useSourceIPAsAnswer, "use-source-ip", false, "Use source IP as answer")
	flag.Parse()

	// Initialize database
	initDB()

	// DNS server setup
	dns.HandleFunc(".", handleRequest)

	server := &dns.Server{Addr: listenAddress, Net: "udp"}
	err := server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n", err.Error())
	}
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./dns.db")
	if err != nil {
		log.Fatal(err)
	}

	createTableQuery := `CREATE TABLE IF NOT EXISTS dns_records (
		id INTEGER PRIMARY KEY,
		qname TEXT,
		answer TEXT,
		UNIQUE(qname)
	);
	CREATE TABLE IF NOT EXISTS dns_queries (
		id INTEGER PRIMARY KEY,
		source_ip TEXT,
		qname TEXT,
		timestamp DATETIME
	);`

	_, err = db.Exec(createTableQuery)
	if err != nil {
		log.Fatal(err)
	}
}

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	ip, _, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil {
		log.Println(err)
		return
	}

	for _, q := range r.Question {
		logQuery(ip, q.Name)

		answer := findAnswer(q.Name, ip)
		rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, answer))
		if err == nil {
			m.Answer = append(m.Answer, rr)
		}
	}

	err = w.WriteMsg(m)
	if err != nil {
		log.Println(err)
	}
}

func logQuery(srcIP, qname string) {
	query := `INSERT INTO dns_queries (source_ip, qname, timestamp) VALUES (?, ?, ?)`
	_, err := db.Exec(query, srcIP, qname, time.Now())
	if err != nil {
		log.Println(err)
	}
}

func findAnswer(qname, srcIP string) string {
	if useSourceIPAsAnswer {
		return srcIP
	}

	var answer string
	err := db.QueryRow("SELECT answer FROM dns_records WHERE qname = ?", qname).Scan(&answer)
	if err != nil {
		return defaultAnswer
	}

	return answer
}
