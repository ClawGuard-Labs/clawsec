package constants

import "strings"


func IsLocalhost(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1" || strings.HasPrefix(ip, "127.")
}

func FileExt(path string) string {
	lastSlash := strings.LastIndex(path, "/")
	base := path[lastSlash+1:]
	lastDot := strings.LastIndex(base, ".")
	if lastDot < 0 {
		return ""
	}
	return strings.ToLower(base[lastDot:])
}

// O_WRONLY=0x1, O_RDWR=0x2, O_CREAT=0x40.
func IsWriteOpen(flags uint32) bool {
	return flags&0x1 != 0 || flags&0x2 != 0 || flags&0x40 != 0
}

func SeverityScore(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 100
	case "high":
		return 70
	case "medium":
		return 40
	case "low":
		return 20
	default: // "info" or unknown
		return 10
	}
}
