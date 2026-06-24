package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

// ── wifi_scan ─────────────────────────────────────────────────────────────────

type WifiNetwork struct {
	SSID     string
	BSSID    string
	Signal   string
	Channel  string
	Security string
}

func wifiScan() ([]WifiNetwork, error) {
	if runtime.GOOS == "darwin" {
		return wifiScanMac()
	}
	if runtime.GOOS == "linux" {
		return wifiScanLinux()
	}
	return nil, fmt.Errorf("wifi scan not supported on %s", runtime.GOOS)
}

func wifiScanMac() ([]WifiNetwork, error) {
	airport := "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
	out, err := exec.Command(airport, "-s").Output()
	if err != nil {
		// try nmcli fallback
		return nil, fmt.Errorf("airport not found: %v", err)
	}

	var networks []WifiNetwork
	lines := bytes.Split(out, []byte("\n"))
	for i, line := range lines {
		if i == 0 {
			continue // header
		}
		s := string(line)
		if len(s) < 40 {
			continue
		}

		// airport output: SSID BSSID RSSI CHANNEL HT CC SECURITY
		fields := strings.Fields(s)
		if len(fields) < 5 {
			continue
		}

		// SSID may have spaces; BSSID is always xx:xx:xx:xx:xx:xx
		bssidIdx := -1
		for j, f := range fields {
			if len(f) == 17 && strings.Count(f, ":") == 5 {
				bssidIdx = j
				break
			}
		}
		if bssidIdx < 1 {
			continue
		}

		ssid := strings.Join(fields[:bssidIdx], " ")
		bssid := fields[bssidIdx]
		signal := ""
		channel := ""
		security := ""
		if bssidIdx+1 < len(fields) {
			signal = fields[bssidIdx+1]
		}
		if bssidIdx+2 < len(fields) {
			channel = fields[bssidIdx+2]
		}
		if bssidIdx+4 < len(fields) {
			security = strings.Join(fields[bssidIdx+4:], " ")
		}

		networks = append(networks, WifiNetwork{
			SSID:     ssid,
			BSSID:    bssid,
			Signal:   signal + " dBm",
			Channel:  channel,
			Security: security,
		})
	}
	return networks, nil
}

func wifiScanLinux() ([]WifiNetwork, error) {
	out, err := exec.Command("nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,CHAN,SECURITY", "dev", "wifi", "list").Output()
	if err != nil {
		return nil, fmt.Errorf("nmcli failed: %v", err)
	}

	var networks []WifiNetwork
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) < 5 {
			continue
		}
		networks = append(networks, WifiNetwork{
			SSID:     parts[0],
			BSSID:    parts[1],
			Signal:   parts[2] + "%",
			Channel:  parts[3],
			Security: parts[4],
		})
	}
	return networks, nil
}

// ── file_watch ────────────────────────────────────────────────────────────────

type FSEvent struct {
	Time string
	Op   string
	Path string
}

func fileWatch(path string, seconds int) ([]FSEvent, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("watcher init failed: %w", err)
	}
	defer watcher.Close()

	if err := watcher.Add(path); err != nil {
		return nil, fmt.Errorf("cannot watch %s: %w", path, err)
	}

	// also watch subdirs
	_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = watcher.Add(p)
		}
		return nil
	})

	var events []FSEvent
	deadline := time.After(time.Duration(seconds) * time.Second)

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return events, nil
			}
			events = append(events, FSEvent{
				Time: time.Now().Format("15:04:05.000"),
				Op:   event.Op.String(),
				Path: event.Name,
			})
		case err, ok := <-watcher.Errors:
			if !ok {
				return events, nil
			}
			_ = err
		case <-deadline:
			return events, nil
		}
	}
}

// ── sys_info ──────────────────────────────────────────────────────────────────

type SysInfo struct {
	OS        string
	Arch      string
	CPU       string
	Cores     int
	TotalRAM  string
	FreeRAM   string
	Hostname  string
	Uptime    string
	DiskTotal string
	DiskFree  string
	Interfaces []NetIface
}

type NetIface struct {
	Name    string
	IP      string
	MAC     string
}

func sysInfo() (*SysInfo, error) {
	info := &SysInfo{
		OS:    runtime.GOOS,
		Arch:  runtime.GOARCH,
		Cores: runtime.NumCPU(),
	}

	// hostname
	info.Hostname, _ = os.Hostname()

	// CPU name
	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("sysctl", "-n", "machdep.cpu.brand_string").Output(); err == nil {
			info.CPU = strings.TrimSpace(string(out))
		}
		// RAM
		if out, err := exec.Command("sysctl", "-n", "hw.memsize").Output(); err == nil {
			var bytes int64
			fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &bytes)
			info.TotalRAM = formatBytes(bytes)
		}
		// Uptime
		if out, err := exec.Command("sysctl", "-n", "kern.boottime").Output(); err == nil {
			info.Uptime = parseBoottime(string(out))
		}
	} else if runtime.GOOS == "linux" {
		if out, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if strings.HasPrefix(line, "model name") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						info.CPU = strings.TrimSpace(parts[1])
						break
					}
				}
			}
		}
		if out, err := os.ReadFile("/proc/meminfo"); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if strings.HasPrefix(line, "MemTotal:") {
					var kb int64
					fmt.Sscanf(line, "MemTotal: %d kB", &kb)
					info.TotalRAM = formatBytes(kb * 1024)
				}
				if strings.HasPrefix(line, "MemAvailable:") {
					var kb int64
					fmt.Sscanf(line, "MemAvailable: %d kB", &kb)
					info.FreeRAM = formatBytes(kb * 1024)
				}
			}
		}
		if out, err := os.ReadFile("/proc/uptime"); err == nil {
			var uptimeSecs float64
			fmt.Sscanf(string(out), "%f", &uptimeSecs)
			info.Uptime = formatDuration(time.Duration(uptimeSecs) * time.Second)
		}
	}

	// disk (cross-platform via df)
	if out, err := exec.Command("df", "-k", "/").Output(); err == nil {
		lines := strings.Split(string(out), "\n")
		if len(lines) > 1 {
			fields := strings.Fields(lines[1])
			if len(fields) >= 4 {
				var total, avail int64
				fmt.Sscanf(fields[1], "%d", &total)
				fmt.Sscanf(fields[3], "%d", &avail)
				info.DiskTotal = formatBytes(total * 1024)
				info.DiskFree = formatBytes(avail * 1024)
			}
		}
	}

	// network interfaces
	ifaces, _ := networkInterfaces()
	info.Interfaces = ifaces

	return info, nil
}

func networkInterfaces() ([]NetIface, error) {
	out, err := exec.Command("ifconfig").Output()
	if err != nil {
		return nil, err
	}

	var ifaces []NetIface
	var current NetIface
	for _, line := range strings.Split(string(out), "\n") {
		if len(line) == 0 {
			continue
		}
		if !strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, " ") {
			if current.Name != "" {
				ifaces = append(ifaces, current)
			}
			fields := strings.Fields(line)
			current = NetIface{Name: strings.TrimSuffix(fields[0], ":")}
		}
		if strings.Contains(line, "inet ") && !strings.Contains(line, "inet6") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) >= 2 {
				current.IP = fields[1]
			}
		}
		if strings.Contains(line, "ether ") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) >= 2 {
				current.MAC = fields[1]
			}
		}
	}
	if current.Name != "" {
		ifaces = append(ifaces, current)
	}
	return ifaces, nil
}

// ── open_files ────────────────────────────────────────────────────────────────

type OpenFile struct {
	PID     string
	Process string
	Type    string
	Name    string
}

func openFiles(filter string) ([]OpenFile, error) {
	args := []string{"-n"}
	if filter != "" {
		// check if it's a PID
		isPID := true
		for _, c := range filter {
			if c < '0' || c > '9' {
				isPID = false
				break
			}
		}
		if isPID {
			args = append(args, "-p", filter)
		} else {
			args = append(args, "-c", filter)
		}
	}

	out, err := exec.Command("lsof", args...).Output()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("lsof failed: %w", err)
	}

	var files []OpenFile
	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if i == 0 {
			continue // header
		}
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		name := strings.Join(fields[8:], " ")
		if name == "" || name == "(deleted)" {
			continue
		}
		files = append(files, OpenFile{
			PID:     fields[1],
			Process: fields[0],
			Type:    fields[4],
			Name:    name,
		})
	}
	return files, nil
}

// ── jwt_decode ────────────────────────────────────────────────────────────────

type JWTInfo struct {
	Algorithm string
	Header    map[string]interface{}
	Payload   map[string]interface{}
	Expires   string
	IssuedAt  string
	Expired   bool
	Warnings  []string
}

func jwtDecode(token string) (*JWTInfo, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT header: %w", err)
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT payload: %w", err)
	}

	var header map[string]interface{}
	var payload map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("invalid JWT header JSON: %w", err)
	}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("invalid JWT payload JSON: %w", err)
	}

	info := &JWTInfo{
		Header:  header,
		Payload: payload,
	}

	if alg, ok := header["alg"].(string); ok {
		info.Algorithm = alg
		if alg == "none" {
			info.Warnings = append(info.Warnings, "Algorithm 'none' — signature is not verified")
		}
		if alg == "HS256" || alg == "HS384" || alg == "HS512" {
			info.Warnings = append(info.Warnings, "HMAC algorithm — secret key must be kept private and should be high entropy")
		}
	}

	if exp, ok := payload["exp"].(float64); ok {
		expTime := time.Unix(int64(exp), 0)
		info.Expires = expTime.UTC().Format(time.RFC3339)
		if time.Now().After(expTime) {
			info.Expired = true
			info.Warnings = append(info.Warnings, fmt.Sprintf("TOKEN EXPIRED at %s", info.Expires))
		} else {
			remaining := time.Until(expTime)
			if remaining < 5*time.Minute {
				info.Warnings = append(info.Warnings, fmt.Sprintf("Token expires in %s", remaining.Round(time.Second)))
			}
		}
	}

	if iat, ok := payload["iat"].(float64); ok {
		info.IssuedAt = time.Unix(int64(iat), 0).UTC().Format(time.RFC3339)
	}

	return info, nil
}

// ── hash_files ────────────────────────────────────────────────────────────────

type HashResult struct {
	Path string
	Hash string
	Size int64
}

func hashFiles(root string) ([]HashResult, error) {
	var results []HashResult

	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("cannot stat %s: %w", root, err)
	}

	if !info.IsDir() {
		data, err := os.ReadFile(root)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		return []HashResult{{Path: root, Hash: fmt.Sprintf("%x", sum), Size: info.Size()}}, nil
	}

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if skipDirs[d.Name()] {
			return filepath.SkipDir
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		sum := sha256.Sum256(data)
		fi, _ := d.Info()
		size := int64(0)
		if fi != nil {
			size = fi.Size()
		}
		results = append(results, HashResult{
			Path: path,
			Hash: fmt.Sprintf("%x", sum),
			Size: size,
		})
		return nil
	})

	return results, err
}

// ── bluetooth_scan ────────────────────────────────────────────────────────────

type BTDevice struct {
	Name    string
	Address string
	Type    string
	RSSI    string
	Paired  bool
}

func bluetoothScan() ([]BTDevice, error) {
	if runtime.GOOS == "darwin" {
		return bluetoothScanMac()
	}
	if runtime.GOOS == "linux" {
		return bluetoothScanLinux()
	}
	return nil, fmt.Errorf("bluetooth scan not supported on %s", runtime.GOOS)
}

func bluetoothScanMac() ([]BTDevice, error) {
	out, err := exec.Command("system_profiler", "SPBluetoothDataType", "-json").Output()
	if err != nil {
		return nil, fmt.Errorf("system_profiler failed: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("json parse failed: %w", err)
	}

	var devices []BTDevice

	bt, ok := result["SPBluetoothDataType"].([]interface{})
	if !ok || len(bt) == 0 {
		return devices, nil
	}

	root, ok := bt[0].(map[string]interface{})
	if !ok {
		return devices, nil
	}

	// paired devices
	if paired, ok := root["device_title"].([]interface{}); ok {
		for _, d := range paired {
			dm, ok := d.(map[string]interface{})
			if !ok {
				continue
			}
			for name, v := range dm {
				info, ok := v.(map[string]interface{})
				if !ok {
					continue
				}
				dev := BTDevice{Name: name, Paired: true}
				if addr, ok := info["device_address"].(string); ok {
					dev.Address = addr
				}
				if t, ok := info["device_minorClassOfDevice_string"].(string); ok {
					dev.Type = t
				}
				devices = append(devices, dev)
			}
		}
	}

	// nearby/not paired
	if nearby, ok := root["device_not_connected"].([]interface{}); ok {
		for _, d := range nearby {
			dm, ok := d.(map[string]interface{})
			if !ok {
				continue
			}
			for name, v := range dm {
				info, ok := v.(map[string]interface{})
				if !ok {
					continue
				}
				dev := BTDevice{Name: name, Paired: false}
				if addr, ok := info["device_address"].(string); ok {
					dev.Address = addr
				}
				if rssi, ok := info["device_rssi"].(string); ok {
					dev.RSSI = rssi
				}
				devices = append(devices, dev)
			}
		}
	}

	return devices, nil
}

func bluetoothScanLinux() ([]BTDevice, error) {
	out, err := exec.Command("bluetoothctl", "devices").Output()
	if err != nil {
		return nil, fmt.Errorf("bluetoothctl failed: %w", err)
	}
	var devices []BTDevice
	for _, line := range strings.Split(string(out), "\n") {
		// format: Device AA:BB:CC:DD:EE:FF Name
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 3 || parts[0] != "Device" {
			continue
		}
		devices = append(devices, BTDevice{
			Address: parts[1],
			Name:    parts[2],
			Paired:  true,
		})
	}
	return devices, nil
}

// ── usb_devices ───────────────────────────────────────────────────────────────

type USBDevice struct {
	Name        string
	Vendor      string
	ProductID   string
	VendorID    string
	Speed       string
	Manufacturer string
}

func usbDevices() ([]USBDevice, error) {
	if runtime.GOOS == "darwin" {
		return usbDevicesMac()
	}
	if runtime.GOOS == "linux" {
		return usbDevicesLinux()
	}
	return nil, fmt.Errorf("usb listing not supported on %s", runtime.GOOS)
}

func usbDevicesMac() ([]USBDevice, error) {
	out, err := exec.Command("system_profiler", "SPUSBDataType", "-json").Output()
	if err != nil {
		return nil, fmt.Errorf("system_profiler failed: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("json parse failed: %w", err)
	}

	var devices []USBDevice
	usb, ok := result["SPUSBDataType"].([]interface{})
	if !ok {
		return devices, nil
	}

	var walk func(items []interface{})
	walk = func(items []interface{}) {
		for _, item := range items {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			dev := USBDevice{}
			if n, ok := m["_name"].(string); ok {
				dev.Name = n
			}
			if vid, ok := m["vendor_id"].(string); ok {
				dev.VendorID = vid
			}
			if pid, ok := m["product_id"].(string); ok {
				dev.ProductID = pid
			}
			if mfr, ok := m["manufacturer"].(string); ok {
				dev.Manufacturer = mfr
			}
			if spd, ok := m["device_speed"].(string); ok {
				dev.Speed = spd
			}
			if dev.Name != "" {
				devices = append(devices, dev)
			}
			if items, ok := m["_items"].([]interface{}); ok {
				walk(items)
			}
		}
	}
	walk(usb)
	return devices, nil
}

func usbDevicesLinux() ([]USBDevice, error) {
	out, err := exec.Command("lsusb").Output()
	if err != nil {
		return nil, fmt.Errorf("lsusb failed: %w", err)
	}
	var devices []USBDevice
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			continue
		}
		// Bus 001 Device 002: ID 1234:5678 Vendor Name
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		idParts := strings.Split(fields[5], ":")
		vid, pid := "", ""
		if len(idParts) == 2 {
			vid = idParts[0]
			pid = idParts[1]
		}
		name := strings.Join(fields[6:], " ")
		devices = append(devices, USBDevice{
			Name:     name,
			VendorID: vid,
			ProductID: pid,
		})
	}
	return devices, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, mins)
	}
	return fmt.Sprintf("%dh %dm", hours, mins)
}

func parseBoottime(s string) string {
	// sysctl kern.boottime: { sec = 1234567890, usec = 0 } Tue Jan 01 00:00:00 2024
	idx := strings.Index(s, "sec = ")
	if idx < 0 {
		return s
	}
	var sec int64
	fmt.Sscanf(s[idx+6:], "%d", &sec)
	boot := time.Unix(sec, 0)
	up := time.Since(boot)
	return formatDuration(up) + " (booted " + boot.Format("2006-01-02 15:04") + ")"
}
