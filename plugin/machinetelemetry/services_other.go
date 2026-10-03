//go:build !linux

package machinetelemetry

// DefaultServicesPlatform reports supported=false: systemd and cgroup v2
// exist only on Linux.
func DefaultServicesPlatform() ServicesPlatform {
	return ServicesPlatform{Unsupported: ReasonNotLinux}
}
