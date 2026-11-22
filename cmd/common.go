package cmd

import (
	"fmt"
	"regexp"

	log "github.com/sirupsen/logrus"

	"github.com/AnixOps/anix-agent/v5/common/layout"
)

const (
	commandName = "anix-agent"
	productName = "AnixOps Agent"
)

var (
	serviceName       = layout.Service + ".service"
	defaultConfigPath = layout.ConfigDir + "/config.json"
)

// Err, Ok and Warn color a terminal message red, green and yellow.
func Err(msg ...any) string  { return color("31", msg) }
func Ok(msg ...any) string   { return color("32", msg) }
func Warn(msg ...any) string { return color("33", msg) }

func color(code string, msg []any) string {
	return "\033[" + code + "m" + fmt.Sprint(msg...) + "\033[0m"
}

// nodeTag matches a node's core tag, [<host>]-<protocol>:<id>.
var nodeTag = regexp.MustCompile(`\[[^\]\s]+\]-[a-z0-9]+:([0-9]+)`)

func hideNodeTags(s string) string { return nodeTag.ReplaceAllString(s, "node-$1") }

// logFormatter names nodes by id only, so the journal shows neither their
// protocol nor the Control host.
type logFormatter struct {
	log.TextFormatter
}

func (f *logFormatter) Format(entry *log.Entry) ([]byte, error) {
	e := *entry
	e.Message = hideNodeTags(entry.Message)
	e.Data = make(log.Fields, len(entry.Data))
	for k, v := range entry.Data {
		switch value := v.(type) {
		case string:
			v = hideNodeTags(value)
		case error:
			v = hideNodeTags(value.Error())
		}
		e.Data[k] = v
	}
	return f.TextFormatter.Format(&e)
}
