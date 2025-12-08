package encrypted

// Logger is a minimal logging interface for capturing detailed trace/debug output.
// It is intentionally compatible with github.com/gologme/log used by yggdrasil-go.
type Logger interface {
	Debugf(string, ...interface{})
	Debugln(...interface{})
	Infof(string, ...interface{})
	Warnf(string, ...interface{})
	Errorf(string, ...interface{})
	Traceln(...interface{})
}

// noopLogger discards all log messages.
type noopLogger struct{}

func (noopLogger) Debugf(string, ...interface{}) {}
func (noopLogger) Debugln(...interface{})        {}
func (noopLogger) Infof(string, ...interface{})  {}
func (noopLogger) Warnf(string, ...interface{})  {}
func (noopLogger) Errorf(string, ...interface{}) {}
func (noopLogger) Traceln(...interface{})        {}
