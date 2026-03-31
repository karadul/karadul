//go:build windows

package tunnel

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// Windows API constants and types
const (
	// Registry key for network adapters
	guidFormat = "{%s}"
)

// Wintun handle types
type wintunAdapterHandle uintptr
type wintunSessionHandle uintptr

// LUID (Locally Unique Identifier) for network interfaces
type luid struct {
	LowPart  uint32
	HighPart int32
}

// Wintun function pointers (lazy-loaded)
var (
	wintunDLL *syscall.LazyDLL

	procCreateAdapter        *syscall.LazyProc
	procCloseAdapter         *syscall.LazyProc
	procStartSession         *syscall.LazyProc
	procEndSession           *syscall.LazyProc
	procGetReadWaitEvent     *syscall.LazyProc
	procReceivePacket        *syscall.LazyProc
	procReleaseReceivePacket *syscall.LazyProc
	procAllocateSendPacket   *syscall.LazyProc
	procSendPacket           *syscall.LazyProc
	procGetAdapterLUID       *syscall.LazyProc
)

func init() {
	wintunDLL = syscall.NewLazyDLL("wintun.dll")

	procCreateAdapter = wintunDLL.NewProc("WintunCreateAdapter")
	procCloseAdapter = wintunDLL.NewProc("WintunCloseAdapter")
	procStartSession = wintunDLL.NewProc("WintunStartSession")
	procEndSession = wintunDLL.NewProc("WintunEndSession")
	procGetReadWaitEvent = wintunDLL.NewProc("WintunGetReadWaitEvent")
	procReceivePacket = wintunDLL.NewProc("WintunReceivePacket")
	procReleaseReceivePacket = wintunDLL.NewProc("WintunReleaseReceivePacket")
	procAllocateSendPacket = wintunDLL.NewProc("WintunAllocateSendPacket")
	procSendPacket = wintunDLL.NewProc("WintunSendPacket")
	procGetAdapterLUID = wintunDLL.NewProc("WintunGetAdapterLUID")
}

// windowsTUN implements Device interface using Wintun
type windowsTUN struct {
	adapter wintunAdapterHandle
	session wintunSessionHandle
	name    string
	luid    uint64
	mtu     int
}

// GUID structure for Windows API
type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// generateGUID creates a new GUID using Windows CoCreateGuid
func generateGUID() (*guid, error) {
	// Load ole32.dll for CoCreateGuid
	ole32 := syscall.NewLazyDLL("ole32.dll")
	procCoCreateGuid := ole32.NewProc("CoCreateGuid")

	var g guid
	ret, _, _ := procCoCreateGuid.Call(uintptr(unsafe.Pointer(&g)))
	if ret != 0 {
		return nil, fmt.Errorf("CoCreateGuid failed: 0x%X", ret)
	}
	return &g, nil
}

// guidToString converts a GUID to string format {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
func guidToString(g *guid) string {
	return fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X-%02X%02X%02X%02X}",
		g.Data1, g.Data2, g.Data3,
		g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
		g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7])
}

// bytesFromPtr creates a byte slice from a C pointer and length.
// The //go:nocheckptr directive prevents false positive race detector warnings
// when working with pointers returned from Wintun DLL syscalls.
//
//go:nocheckptr
func bytesFromPtr(ptr uintptr, length int) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(ptr)), length)
}

// ptrToBytePtr converts a uintptr to a *byte for C interop.
// The //go:nocheckptr directive prevents false positive race detector warnings.
//
//go:nocheckptr
func ptrToBytePtr(ptr uintptr) *byte {
	return (*byte)(unsafe.Pointer(ptr))
}

// getAdapterLUID retrieves the LUID for the adapter
func getAdapterLUID(adapter wintunAdapterHandle) (uint64, error) {
	var l luid
	ret, _, errno := procGetAdapterLUID.Call(
		uintptr(adapter),
		uintptr(unsafe.Pointer(&l)),
	)
	if ret == 0 {
		return 0, fmt.Errorf("WintunGetAdapterLUID failed: %v", errno)
	}
	return uint64(uint64(l.HighPart)<<32) | uint64(l.LowPart), nil
}

// luidToInterfaceIndex converts a LUID to a network interface index
func luidToInterfaceIndex(luidVal uint64) (int, error) {
	// Load iphlpapi.dll for ConvertInterfaceLuidToIndex
	iphlpapi := syscall.NewLazyDLL("iphlpapi.dll")
	procConvertLuidToIndex := iphlpapi.NewProc("ConvertInterfaceLuidToIndex")

	// Convert uint64 back to luid struct
	l := luid{
		LowPart:  uint32(luidVal),
		HighPart: int32(luidVal >> 32),
	}
	var index uint32
	ret, _, _ := procConvertLuidToIndex.Call(
		uintptr(unsafe.Pointer(&l)),
		uintptr(unsafe.Pointer(&index)),
	)
	if ret != 0 {
		return 0, fmt.Errorf("ConvertInterfaceLuidToIndex failed: 0x%X", ret)
	}
	return int(index), nil
}

// CreateTUN creates a TUN device on Windows using Wintun.
// The name parameter is used as the adapter name (e.g., "Karadul").
func CreateTUN(name string) (Device, error) {
	// Check if DLL is available
	if err := wintunDLL.Load(); err != nil {
		return nil, fmt.Errorf("wintun.dll not found: %w (download from https://www.wintun.net/)", err)
	}

	// Generate a GUID for the adapter
	g, err := generateGUID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate GUID: %w", err)
	}

	// Convert GUID to UTF-16 for Windows API
	guidStr := guidToString(g)
	guidUTF16, err := syscall.UTF16PtrFromString(guidStr)
	if err != nil {
		return nil, fmt.Errorf("failed to convert GUID to UTF16: %w", err)
	}

	// Use provided name or default
	adapterName := name
	if adapterName == "" {
		adapterName = "Karadul"
	}

	// Convert name to UTF-16
	nameUTF16, err := syscall.UTF16PtrFromString(adapterName)
	if err != nil {
		return nil, fmt.Errorf("failed to convert name to UTF16: %w", err)
	}

	// Tunnel type (shows up in network adapter properties)
	tunnelTypeUTF16, err := syscall.UTF16PtrFromString("Karadul")
	if err != nil {
		return nil, fmt.Errorf("failed to convert tunnel type to UTF16: %w", err)
	}

	// Create the adapter
	ret, _, errno := procCreateAdapter.Call(
		uintptr(unsafe.Pointer(nameUTF16)),
		uintptr(unsafe.Pointer(tunnelTypeUTF16)),
		uintptr(unsafe.Pointer(guidUTF16)),
	)

	if ret == 0 {
		return nil, fmt.Errorf("WintunCreateAdapter failed: %v (try running as Administrator)", errno)
	}

	adapter := wintunAdapterHandle(ret)

	// Get adapter LUID for later use
	adapterLUID, err := getAdapterLUID(adapter)
	if err != nil {
		procCloseAdapter.Call(uintptr(adapter))
		return nil, fmt.Errorf("failed to get adapter LUID: %w", err)
	}

	// Start session with default capacity (4MB ring buffer)
	const capacity = 0x400000
	ret, _, errno = procStartSession.Call(uintptr(adapter), uintptr(capacity))
	if ret == 0 {
		procCloseAdapter.Call(uintptr(adapter))
		return nil, fmt.Errorf("WintunStartSession failed: %v", errno)
	}

	session := wintunSessionHandle(ret)

	// Get the actual interface name from the adapter
	// On Windows, this is the same as what we provided, but we query it for consistency
	ifaceName := adapterName

	tun := &windowsTUN{
		adapter: adapter,
		session: session,
		name:    ifaceName,
		luid:    adapterLUID,
		mtu:     1420,
	}

	return tun, nil
}

func (t *windowsTUN) Name() string {
	return t.name
}

func (t *windowsTUN) MTU() int {
	return t.mtu
}

// GetReadWaitEvent returns a Windows event handle that is signaled when
// data is available to read. This can be used with WaitForSingleObject
// for async I/O.
func (t *windowsTUN) GetReadWaitEvent() (uintptr, error) {
	ret, _, errno := procGetReadWaitEvent.Call(uintptr(t.session))
	if ret == 0 {
		return 0, fmt.Errorf("WintunGetReadWaitEvent failed: %v", errno)
	}
	return ret, nil
}

// WaitForData blocks until data is available to read or the timeout expires.
// Returns true if data is available, false if timeout expired.
func (t *windowsTUN) WaitForData(timeout time.Duration) (bool, error) {
	event, err := t.GetReadWaitEvent()
	if err != nil {
		return false, err
	}

	// Load kernel32.dll for WaitForSingleObject
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procWaitForSingleObject := kernel32.NewProc("WaitForSingleObject")

	ms := uint32(timeout.Milliseconds())
	if timeout < 0 {
		ms = 0xFFFFFFFF // INFINITE
	}

	ret, _, _ := procWaitForSingleObject.Call(event, uintptr(ms))
	switch ret {
	case 0: // WAIT_OBJECT_0
		return true, nil
	case 0x102: // WAIT_TIMEOUT
		return false, nil
	default:
		return false, fmt.Errorf("WaitForSingleObject failed: 0x%X", ret)
	}
}

func (t *windowsTUN) Read(buf []byte) (int, error) {
	// WintunReceivePacket blocks until a packet is available
	// It returns a pointer to the packet and sets packetSize to the packet length
	var packetSize uint32

	ret, _, errno := procReceivePacket.Call(
		uintptr(t.session),
		uintptr(unsafe.Pointer(&packetSize)),
	)

	if ret == 0 {
		return 0, fmt.Errorf("WintunReceivePacket failed: %v", errno)
	}

	packetPtr := ret

	// Copy packet data to provided buffer
	n := int(packetSize)
	if n > len(buf) {
		// Release the packet before returning error.
		procReleaseReceivePacket.Call(uintptr(t.session), packetPtr)
		return 0, fmt.Errorf("packet too large: %d bytes (buffer %d)", packetSize, len(buf))
	}

	// Copy from packet pointer to buffer
	src := bytesFromPtr(packetPtr, int(packetSize))
	copied := copy(buf, src[:n])

	// Release the packet back to Wintun
	procReleaseReceivePacket.Call(uintptr(t.session), packetPtr)

	return copied, nil
}

func (t *windowsTUN) Write(buf []byte) (int, error) {
	// Allocate a packet for sending
	ret, _, errno := procAllocateSendPacket.Call(
		uintptr(t.session),
		uintptr(len(buf)),
	)

	if ret == 0 {
		return 0, fmt.Errorf("WintunAllocateSendPacket failed: %v", errno)
	}

	packetPtr := ret

	// Copy data to packet
	dst := bytesFromPtr(packetPtr, len(buf))
	copy(dst, buf)

	// Send the packet
	procSendPacket.Call(uintptr(t.session), packetPtr)

	return len(buf), nil
}

// getInterfaceIndex returns the interface index for netsh commands
func (t *windowsTUN) getInterfaceIndex() (int, error) {
	idx, err := luidToInterfaceIndex(t.luid)
	if err != nil {
		// Fallback: try to find interface by name
		ifaces, err := net.Interfaces()
		if err != nil {
			return 0, err
		}
		for _, iface := range ifaces {
			if iface.Name == t.name {
				return iface.Index, nil
			}
		}
		return 0, fmt.Errorf("interface not found")
	}
	return idx, nil
}

func (t *windowsTUN) SetMTU(mtu int) error {
	// Get interface index for more reliable netsh commands
	idx, err := t.getInterfaceIndex()
	if err != nil {
		// Fallback to interface name
		cmd := exec.Command("netsh", "interface", "ipv4", "set", "subinterface",
			fmt.Sprintf("\"%s\"", t.name),
			fmt.Sprintf("mtu=%d", mtu),
			"store=persistent")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to set MTU: %w: %s", err, out)
		}
	} else {
		// Use interface index
		cmd := exec.Command("netsh", "interface", "ipv4", "set", "subinterface",
			strconv.Itoa(idx),
			fmt.Sprintf("mtu=%d", mtu),
			"store=persistent")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to set MTU: %w: %s", err, out)
		}
	}

	t.mtu = mtu
	return nil
}

func (t *windowsTUN) SetAddr(ip net.IP, prefixLen int) error {
	ip4 := ip.To4()
	if ip4 != nil {
		return t.setAddr4(ip4, prefixLen)
	}
	return t.setAddr6(ip, prefixLen)
}

func (t *windowsTUN) setAddr4(ip net.IP, prefixLen int) error {
	// Calculate subnet mask from prefix length
	mask := net.CIDRMask(prefixLen, 32)
	maskStr := fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])

	// Get interface index for more reliable commands
	idx, err := t.getInterfaceIndex()
	if err != nil {
		// Fallback to interface name
		idx = -1
	}

	var cmd *exec.Cmd
	if idx >= 0 {
		// Use interface index (more reliable)
		cmd = exec.Command("netsh", "interface", "ip", "set", "address",
			strconv.Itoa(idx),
			"static",
			ip.String(),
			maskStr)
	} else {
		// Fallback to name
		cmd = exec.Command("netsh", "interface", "ip", "set", "address",
			fmt.Sprintf("name=\"%s\"", t.name),
			"static",
			ip.String(),
			maskStr)
	}

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set IPv4 address: %w: %s", err, out)
	}

	return nil
}

func (t *windowsTUN) setAddr6(ip net.IP, prefixLen int) error {
	// Get interface index for more reliable commands
	idx, err := t.getInterfaceIndex()
	if err != nil {
		idx = -1
	}

	var cmd *exec.Cmd
	if idx >= 0 {
		cmd = exec.Command("netsh", "interface", "ipv6", "set", "address",
			strconv.Itoa(idx),
			fmt.Sprintf("%s/%d", ip.String(), prefixLen),
			"store=persistent")
	} else {
		cmd = exec.Command("netsh", "interface", "ipv6", "set", "address",
			fmt.Sprintf("interface=\"%s\"", t.name),
			fmt.Sprintf("%s/%d", ip.String(), prefixLen),
			"store=persistent")
	}

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set IPv6 address: %w: %s", err, out)
	}

	return nil
}

func (t *windowsTUN) AddRoute(dst *net.IPNet) error {
	// Get our interface IP and index
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to list interfaces: %w", err)
	}

	var gateway string
	var ifaceIndex int
	for _, iface := range ifaces {
		if iface.Name == t.name {
			ifaceIndex = iface.Index
			addrs, err := iface.Addrs()
			if err != nil {
				return fmt.Errorf("failed to get interface addresses: %w", err)
			}
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok {
					if ipnet.IP.To4() != nil {
						gateway = ipnet.IP.String()
						break
					}
				}
			}
			break
		}
	}

	if gateway == "" {
		return fmt.Errorf("cannot determine gateway IP for route (SetAddr must be called first)")
	}

	isIPv6 := dst.IP.To4() == nil

	var cmd *exec.Cmd
	if isIPv6 {
		// IPv6 route: route add dst/prefix gateway if index
		cmd = exec.Command("route", "add", dst.String(), gateway, "if", strconv.Itoa(ifaceIndex))
	} else {
		// IPv4 route: route add dst mask netmask gateway if index
		mask := dst.Mask
		maskStr := fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
		cmd = exec.Command("route", "add", dst.IP.String(), "mask", maskStr, gateway, "if", strconv.Itoa(ifaceIndex))
	}

	if out, err := cmd.CombinedOutput(); err != nil {
		// Route might already exist, which is okay
		if !strings.Contains(string(out), "already exists") {
			return fmt.Errorf("failed to add route: %w: %s", err, out)
		}
	}

	return nil
}

func (t *windowsTUN) Close() error {
	var firstErr error

	// End the session
	if t.session != 0 {
		_, _, err := procEndSession.Call(uintptr(t.session))
		if err != syscall.Errno(0) && firstErr == nil {
			firstErr = fmt.Errorf("WintunEndSession failed: %v", err)
		}
		t.session = 0
	}

	// Close the adapter
	if t.adapter != 0 {
		_, _, err := procCloseAdapter.Call(uintptr(t.adapter))
		if err != syscall.Errno(0) && firstErr == nil {
			firstErr = fmt.Errorf("WintunCloseAdapter failed: %v", err)
		}
		t.adapter = 0
	}

	return firstErr
}
