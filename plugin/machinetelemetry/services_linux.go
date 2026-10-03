//go:build linux

package machinetelemetry

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/godbus/dbus/v5"
)

const (
	systemdBusName       = "org.freedesktop.systemd1"
	systemdObjectPath    = dbus.ObjectPath("/org/freedesktop/systemd1")
	systemdManagerIface  = "org.freedesktop.systemd1.Manager"
	systemdServiceIface  = "org.freedesktop.systemd1.Service"
	systemdPrivateSocket = "unix:path=/run/systemd/private"
)

// DefaultServicesPlatform reads the host's systemd over D-Bus and its
// cgroup v2 hierarchy.
func DefaultServicesPlatform() ServicesPlatform {
	return ServicesPlatform{
		CgroupRoot:        DefaultCgroupRoot,
		SystemdRuntimeDir: DefaultSystemdRuntimeDir,
		Connect:           connectSystemd,
	}
}

type dbusLister struct{ conn *dbus.Conn }

// connectSystemd connects to the system bus, or straight to systemd's
// private socket (root only) on a host without a bus daemon. The connection
// is kept across collections, so it is not bound to a context:
// dbus.WithContext would close it when the context ends. Each call is
// bounded by its own context instead.
func connectSystemd(context.Context) (ServiceLister, error) {
	conn, busErr := dbus.ConnectSystemBus()
	if busErr == nil {
		return &dbusLister{conn: conn}, nil
	}
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("connect to the system bus: %w", busErr)
	}
	conn, err := dbus.Dial(systemdPrivateSocket)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("connect to the system bus: %w", busErr), fmt.Errorf("connect to systemd: %w", err))
	}
	if err := conn.Auth(nil); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("authenticate to systemd: %w", err)
	}
	return &dbusLister{conn: conn}, nil
}

// listedUnit is one ListUnits row, (ssssssouso). Only Name, LoadState,
// ActiveState and SubState are kept; the Description is dropped here.
type listedUnit struct {
	Name        string
	Description string
	LoadState   string
	ActiveState string
	SubState    string
	Following   string
	Path        dbus.ObjectPath
	JobID       uint32
	JobType     string
	JobPath     dbus.ObjectPath
}

func (l *dbusLister) ListServices(ctx context.Context) ([]ServiceUnit, error) {
	var rows []listedUnit
	call := l.conn.Object(systemdBusName, systemdObjectPath).CallWithContext(ctx, systemdManagerIface+".ListUnits", 0)
	if err := call.Store(&rows); err != nil {
		return nil, fmt.Errorf("systemd ListUnits: %w", err)
	}
	units := make([]ServiceUnit, 0, len(rows))
	for _, row := range rows {
		if !strings.HasSuffix(row.Name, ".service") {
			continue
		}
		units = append(units, ServiceUnit{
			Name: row.Name, LoadState: row.LoadState, ActiveState: row.ActiveState, SubState: row.SubState,
		})
	}
	return units, nil
}

func (l *dbusLister) ControlGroup(ctx context.Context, unit ServiceUnit) (string, error) {
	var value dbus.Variant
	object := l.conn.Object(systemdBusName, unitObjectPath(unit.Name))
	call := object.CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, systemdServiceIface, "ControlGroup")
	if err := call.Store(&value); err != nil {
		return "", err
	}
	cgroup, ok := value.Value().(string)
	if !ok {
		return "", errors.New("ControlGroup is not a string")
	}
	return cgroup, nil
}

func (l *dbusLister) Close() error {
	if l == nil || l.conn == nil {
		return nil
	}
	return l.conn.Close()
}

// unitObjectPath is systemd's bus path of a unit: every byte outside
// [A-Za-z0-9] is escaped as _XX (sd_bus_path_encode).
func unitObjectPath(name string) dbus.ObjectPath {
	var builder strings.Builder
	builder.WriteString("/org/freedesktop/systemd1/unit/")
	for index := 0; index < len(name); index++ {
		character := name[index]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') {
			builder.WriteByte(character)
			continue
		}
		fmt.Fprintf(&builder, "_%02x", character)
	}
	return dbus.ObjectPath(builder.String())
}
