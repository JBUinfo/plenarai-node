package setup

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// ProgressMode controls how progress is displayed.
type ProgressMode int

const (
	ProgressUI    ProgressMode = iota // animated progress bar with \r
	ProgressQuiet                     // periodic plain percentage lines
	ProgressOff                       // no output
)

var DefaultProgressMode = ProgressUI

// ProgressReader wraps an io.Reader and reports progress.
type ProgressReader struct {
	reader     io.Reader
	total      int64
	read       int64
	label      string
	mode       ProgressMode
	lastUpdate time.Time
	lastShown  int
}

func NewProgressReader(r io.Reader, total int64, label string) *ProgressReader {
	return &ProgressReader{
		reader: r,
		total:  total,
		label:  label,
		mode:   DefaultProgressMode,
	}
}

func (p *ProgressReader) Read(buf []byte) (int, error) {
	n, err := p.reader.Read(buf)
	p.read += int64(n)
	p.render()
	return n, err
}

func (p *ProgressReader) render() {
	if p.mode == ProgressOff {
		return
	}
	now := time.Now()
	if now.Sub(p.lastUpdate) < 200*time.Millisecond && p.read < p.total {
		return
	}
	p.lastUpdate = now

	pct := 0
	if p.total > 0 {
		pct = int(float64(p.read) / float64(p.total) * 100)
	}

	switch p.mode {
	case ProgressUI:
		barWidth := 30
		filled := pct * barWidth / 100
		bar := strings.Repeat("=", filled) + strings.Repeat(" ", barWidth-filled)
		fmt.Printf("\r%s [%s] %3d%% (%s / %s)", p.label, bar, pct, formatBytes(p.read), formatBytes(p.total))
		if p.read >= p.total {
			fmt.Println()
		}
	case ProgressQuiet:
		// print only at every 10% jump
		if pct/10 != p.lastShown/10 || p.read >= p.total {
			fmt.Printf("%s: %d%% (%s / %s)\n", p.label, pct, formatBytes(p.read), formatBytes(p.total))
		}
	}
	p.lastShown = pct
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
