//go:build !linux

package node

// hostInterfaces reports nothing off Linux.
func hostInterfaces() ([]observedInterface, error) { return nil, nil }
