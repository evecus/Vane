//go:build !windows

package api

import (
	"fmt"
	"syscall"
)

// readSysinfoDisk reads disk usage for a given mount point via syscall.Statfs.
func readSysinfoDisk(mountPoint string) map[string]interface{} {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(mountPoint, &stat); err != nil {
		return nil
	}
	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)
	used := total - free
	totalKB := total / 1024
	usedKB := used / 1024
	if totalKB == 0 {
		return nil
	}
	pct := fmt.Sprintf("%.1f", float64(usedKB)/float64(totalKB)*100)
	return map[string]interface{}{
		"total_kb": totalKB,
		"used_kb":  usedKB,
		"pct":      pct,
	}
}
