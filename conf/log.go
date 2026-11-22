package conf

// LogConfig is the Log section.
type LogConfig struct {
	// Level is a logrus level (default info).
	Level string `json:"Level"`
	// Output is a file to log to; empty logs to stdout.
	Output string `json:"Output"`
}
