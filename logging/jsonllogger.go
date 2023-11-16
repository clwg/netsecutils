package jsonllogger

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type LoggerConfig struct {
	LogDir         string
	FilenamePrefix string
	MaxLines       int
	RotationTime   time.Duration
}

type Logger struct {
	config      LoggerConfig
	currentFile *os.File
	lineCount   int
	mu          sync.Mutex
}

// NewLogger creates a new logger instance
func NewLogger(config LoggerConfig) (*Logger, error) {
	logger := &Logger{
		config: config,
	}
	err := logger.rotateFile()
	if err != nil {
		return nil, err
	}
	go logger.timeBasedRotation()
	return logger, nil
}

// Log logs the given object to the current log file
func (l *Logger) Log(obj interface{}) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	line, err := json.Marshal(obj)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(l.currentFile, string(line))
	if err != nil {
		return err
	}

	l.lineCount++
	if l.lineCount >= l.config.MaxLines {
		return l.rotateFile()
	}

	return nil
}

// rotateFile rotates and compresses the log file
func (l *Logger) rotateFile() error {
	// Check if log directory exists, if not, create it
	if _, err := os.Stat(l.config.LogDir); os.IsNotExist(err) {
		if err := os.MkdirAll(l.config.LogDir, 0755); err != nil {
			return err
		}
	}

	if l.currentFile != nil {
		// Open a gzip writer to compress the existing file
		archiveDir := filepath.Join(l.config.LogDir, "archive") // Define the archive directory
		if _, err := os.Stat(archiveDir); os.IsNotExist(err) {
			if err := os.MkdirAll(archiveDir, 0755); err != nil { // Create archive directory if it does not exist
				return err
			}
		}
		gzipFilename := filepath.Join(archiveDir, fmt.Sprintf("%s.gz", filepath.Base(l.currentFile.Name())))
		gzipFile, err := os.Create(gzipFilename)
		if err != nil {
			return err
		}
		writer := gzip.NewWriter(gzipFile)
		l.currentFile.Seek(0, 0)                                  // Move to start of file
		if _, err := io.Copy(writer, l.currentFile); err != nil { // Copy the contents of the file to the gzip writer
			return err
		}
		writer.Close()
		gzipFile.Close()
		originalFileName := l.currentFile.Name() // Storing the original filename for deletion
		l.currentFile.Close()

		// Remove the original file after compression
		if err := os.Remove(originalFileName); err != nil {
			return err
		}
	}

	filename := fmt.Sprintf("%s_%s.log", l.config.FilenamePrefix, time.Now().Format(time.RFC3339))
	// Use filepath.Join to combine the directory and filename
	fullPath := filepath.Join(l.config.LogDir, filename)
	file, err := os.Create(fullPath)
	if err != nil {
		return err
	}

	l.currentFile = file
	l.lineCount = 0
	return nil
}

// timeBasedRotation rotates the log file based on the given rotation time
func (l *Logger) timeBasedRotation() {
	for range time.Tick(l.config.RotationTime) {
		l.mu.Lock()
		l.rotateFile()
		l.mu.Unlock()
	}
}