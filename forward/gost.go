package forward

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

const (
	// DefaultGostDir is where the removed gost driver kept gost's
	// configuration and link certificate.
	DefaultGostDir = "/var/lib/anixops-gost"
	// DefaultGostUnit is the unit the removed gost driver ran gost as.
	DefaultGostUnit = "anixops-gost.service"
	// gostConfig is the file anixops-gost.service needs to start
	// (ConditionPathExists).
	gostConfig = "gost.json"
)

// RetireGost stops the gost a previous Agent ran and clears its directory,
// so that anixops-gost.service does not start again (its unit needs
// gost.json). The Agent may stop the unit (the installer's polkit rule) and
// owns the directory; the installer and the updater remove the unit file
// and the binary. Nothing happens on a host that never ran gost.
func RetireGost(ctx context.Context, settings GostSettings) {
	dir := settings.Dir
	if dir == "" {
		dir = DefaultGostDir
	}
	if _, err := os.Stat(filepath.Join(dir, gostConfig)); err != nil {
		return
	}
	unit := settings.Unit
	if unit == "" {
		unit = DefaultGostUnit
	}
	systemctl := settings.Systemctl
	if systemctl == "" {
		systemctl = "systemctl"
	}
	logger := log.WithFields(log.Fields{"component": "forward", "unit": unit, "dir": dir})
	// #nosec G204 -- the binary and unit come from the Agent's configuration.
	if out, err := exec.CommandContext(ctx, systemctl, "stop", unit).CombinedOutput(); err != nil {
		logger.WithError(err).WithField("output", string(out)).Warn("Could not stop the retired gost")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		logger.WithError(err).Warn("Could not clear the retired gost's directory")
		return
	}
	var errs []error
	for _, entry := range entries {
		errs = append(errs, os.RemoveAll(filepath.Join(dir, entry.Name())))
	}
	if err := errors.Join(errs...); err != nil {
		logger.WithError(err).Warn("Could not clear the retired gost's directory")
		return
	}
	logger.Info("Retired gost: stopped and cleared (its routes run on the network model)")
}
