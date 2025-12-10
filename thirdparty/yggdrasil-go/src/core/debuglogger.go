package core

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type plaintextLogger struct {
	mu   sync.Mutex
	w    *bufio.Writer
	path string
}

func newPlaintextLogger(path string) (*plaintextLogger, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("failed to create debug log directory: %w", err)
		}
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("failed to open debug log file: %w", err)
	}

	return &plaintextLogger{w: bufio.NewWriter(f), path: path}, nil
}

func (l *plaintextLogger) log(direction string, peer ed25519.PublicKey, data []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()

	line := fmt.Sprintf(
		"[PLAINTEXT %s] ts=%d peer=%s len=%d data=%s",
		direction,
		time.Now().UnixMilli(),
		hex.EncodeToString(peer),
		len(data),
		hex.EncodeToString(data),
	)

	if _, err := l.w.WriteString(line + "\n"); err != nil {
		return
	}

	_ = l.w.Flush()
}
