package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	jsonllogger "github.com/clwg/netsecutils/pkg/logging"
	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
)

// DNSQuery represents a DNS query with source IP, query name, and timestamp.
type DNSQuery struct {
	SourceIP  string
	Query     string
	Answer    string
	Timestamp time.Time
}

// AppConfig holds configuration data.
type AppConfig struct {
	DefaultAnswer       string
	ListenAddress       string
	UseSourceIPAsAnswer bool
	LoggerConfig        jsonllogger.LoggerConfig
}

func main() {
	appConfig := parseFlags()

	jsonLogger, err := jsonllogger.NewLogger(appConfig.LoggerConfig)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	db, err := initDB()
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	server := setupDNSServer(appConfig, db, jsonLogger)
	err = server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start DNS server: %v", err)
	}
	defer server.Shutdown()
}

// parseFlags parses command-line flags into an AppConfig.
func parseFlags() AppConfig {
	var config AppConfig

	flag.StringVar(&config.DefaultAnswer, "default-answer", "127.0.0.1", "Default answer for DNS queries")
	flag.StringVar(&config.ListenAddress, "listen", ":53", "The address to listen on for DNS queries")
	flag.BoolVar(&config.UseSourceIPAsAnswer, "use-source-ip", false, "Use source IP as answer")

	filenamePrefix := flag.String("filenamePrefix", "dnsauthoritysink", "Prefix for log filenames")
	logDir := flag.String("logDir", "./logs", "Directory for log files")
	maxLines := flag.Int("maxLines", 10000, "Maximum number of lines per log file")
	rotationTime := flag.Int("rotationTime", 60, "Log rotation time in minutes")

	flag.Parse()

	config.LoggerConfig = jsonllogger.LoggerConfig{
		FilenamePrefix: *filenamePrefix,
		LogDir:         *logDir,
		MaxLines:       *maxLines,
		RotationTime:   time.Duration(*rotationTime) * time.Minute,
	}

	return config
}

// initDB initializes and returns a new database connection.
func initDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "./dns.db")
	if err != nil {
		return nil, err
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
		return nil, err
	}

	return db, nil
}

// setupDNSServer sets up and returns a new DNS server.
func setupDNSServer(config AppConfig, db *sql.DB, jsonLogger *jsonllogger.Logger) *dns.Server {
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		handleRequest(w, r, db, jsonLogger, config)
	})
	server := &dns.Server{Addr: config.ListenAddress, Net: "udp"}
	return server
}

// handleRequest handles incoming DNS requests.
func handleRequest(w dns.ResponseWriter, r *dns.Msg, db *sql.DB, jsonLogger *jsonllogger.Logger, config AppConfig) {
	m := new(dns.Msg)
	m.SetReply(r)

	ip, _, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil {
		log.Println(err)
		return
	}

	for _, q := range r.Question {

		answer := findAnswer(db, q.Name, ip, config.UseSourceIPAsAnswer, config.DefaultAnswer)
		rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, answer))
		if err == nil {
			m.Answer = append(m.Answer, rr)
		}
		logQuery(db, jsonLogger, ip, q.Name, answer, time.Now())
	}

	err = w.WriteMsg(m)
	if err != nil {
		log.Println(err)
	}
}

// logQuery logs a DNS query to the database and JSON logger.
func logQuery(db *sql.DB, jsonLogger *jsonllogger.Logger, srcIP, qname string, answer string, timestamp time.Time) {
	dnsQuery := DNSQuery{
		SourceIP:  srcIP,
		Query:     qname,
		Answer:    answer,
		Timestamp: timestamp,
	}
	jsonLogger.Log(dnsQuery)

	query := `INSERT INTO dns_queries (source_ip, qname, timestamp) VALUES (?, ?, ?)`
	_, err := db.Exec(query, srcIP, qname, timestamp)
	if err != nil {
		log.Println(err)
	}
}

// findAnswer finds the DNS answer for a given query name.
func findAnswer(db *sql.DB, qname, srcIP string, useSrcIP bool, defaultAnswer string) string {
	if useSrcIP {
		return srcIP
	}

	var answer string
	err := db.QueryRow("SELECT answer FROM dns_records WHERE qname = ?", qname).Scan(&answer)
	if err != nil {
		return defaultAnswer
	}

	return answer
}
