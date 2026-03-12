//go:build windows

package api

// readSysinfoDisk is not implemented on Windows — disk stats via syscall.Statfs
// are unavailable. Returns nil so the sysinfo endpoint gracefully omits disk data.
func readSysinfoDisk(_ string) map[string]interface{} {
	return nil
}
