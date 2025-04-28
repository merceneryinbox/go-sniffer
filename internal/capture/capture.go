package capture

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var headerPrinted = false
var localIPs map[string]bool
var pidPortMap map[string]string
var pidNameMap map[string]string
var servicesMap map[string]string
var mappingMutex sync.RWMutex

func init() {
	localIPs = make(map[string]bool)
	pidPortMap = make(map[string]string)
	pidNameMap = make(map[string]string)
	servicesMap = make(map[string]string)
	loadLocalIPs()
	loadPIDPortMapping()
	loadPIDNameMapping()
}

func loadLocalIPs() {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Printf("Ошибка получения интерфейсов: %v", err)
		return
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ipv4 := ip.To4(); ipv4 != nil {
				localIPs[ipv4.String()] = true
			}
		}
	}
}

func isLocalIP(ip string) bool {
	return localIPs[ip]
}

func CapturePacketsOnInterfaces(devices []string) {
	go updatePIDMappingsLoop()
	for _, device := range devices {
		go captureDevice(device)
	}
	select {}
}

func updatePIDMappingsLoop() {
	for {
		loadPIDPortMapping()
		loadPIDNameMapping()
		time.Sleep(5 * time.Second)
	}
}

// Умное определение приложения через порт + протокол
func detectAppTypeBySystem(port uint16, protocol string) string {
	key := fmt.Sprintf("%d/%s", port, strings.ToLower(protocol))
	if service, ok := servicesMap[key]; ok {
		return fmt.Sprintf("%s(%d)", service, port)
	}
	return fmt.Sprintf("Unknown(%d)", port)
}

// CapturePackets запускает захват пакетов на указанном интерфейсе
func CapturePackets(device string) {
	snapshotLen := int32(65535)  // Захватываем ВСЕ пакеты целиком
	promiscuous := false         // Можно true если хочешь видеть чужой трафик
	timeout := pcap.BlockForever // Ждём пакеты бесконечно
	handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatalf("Ошибка открытия устройства: %v", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Println("Начинаем захват пакетов на интерфейсе:", device)

	for packet := range packetSource.Packets() {
		processPacket(packet)
	}
}

func captureDevice(device string) {
	handle, err := pcap.OpenLive(device, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Ошибка открытия устройства %s: %v", device, err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Println("Начинаем захват на интерфейсе:", device)

	for packet := range packetSource.Packets() {
		processPacket(packet)
	}
}

func processPacket(packet gopacket.Packet) {
	srcIP := "-"
	dstIP := "-"
	src := "-"
	dst := "-"
	networkType := "-"
	transportType := "-"
	payloadSize := 0
	tcpFlags := "-"
	appType := "-"
	pidInfo := "-"
	payloadSnippet := "-"
	var srcPort, dstPort uint16

	if ethernetLayer := packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil {
		networkType = "Ethernet"
	}
	if ip4Layer, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		srcIP = ip4Layer.SrcIP.String()
		dstIP = ip4Layer.DstIP.String()
		src = srcIP
		dst = dstIP
		networkType = "IPv4"
	}
	if ip6Layer, ok := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
		srcIP = ip6Layer.SrcIP.String()
		dstIP = ip6Layer.DstIP.String()
		src = srcIP
		dst = dstIP
		networkType = "IPv6"
	}

	if tcpLayer, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		src = fmt.Sprintf("%s:%d", src, tcpLayer.SrcPort)
		dst = fmt.Sprintf("%s:%d", dst, tcpLayer.DstPort)
		srcPort = uint16(tcpLayer.SrcPort)
		dstPort = uint16(tcpLayer.DstPort)
		transportType = "TCP"
		payloadSize = len(tcpLayer.Payload)
		tcpFlags = tcpFlagString(tcpLayer)
		payloadSnippet = safeSnippet(tcpLayer.Payload)
	}
	if udpLayer, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
		src = fmt.Sprintf("%s:%d", src, udpLayer.SrcPort)
		dst = fmt.Sprintf("%s:%d", dst, udpLayer.DstPort)
		srcPort = uint16(udpLayer.SrcPort)
		dstPort = uint16(udpLayer.DstPort)
		transportType = "UDP"
		payloadSize = len(udpLayer.Payload)
		payloadSnippet = safeSnippet(udpLayer.Payload)
	}

	selectedPort := dstPort
	if isLocalIP(srcIP) {
		selectedPort = srcPort
	}

	appType = detectAppTypeBySystem(selectedPort, transportType)
	pid := lookupPID(selectedPort, transportType)
	pidInfo = lookupProcessName(pid)

	if strings.HasPrefix(appType, "Unknown(") && pidInfo != "-" {
		appType = pidInfo
	}

	if !isLocalIP(srcIP) && !isLocalIP(dstIP) {
		return
	}

	if !headerPrinted {
		fmt.Println("==========================================================================================================================================================================================================================================")
		fmt.Printf("| %-20s | %-13s | %-24s | %-24s | %-10s | %-12s | %-13s | %-12s | %-23s | %-28s | %-20s |\n",
			"Время получения",
			"Размер (байт)",
			"Источник (IP:Порт)",
			"Назначение (IP:Порт)",
			"Сеть",
			"Транспорт",
			"Payload (байт)",
			"TCP Флаги",
			"Приложение",
			"PID/Приложение",
			"Сниппет Payload")
		fmt.Println("==========================================================================================================================================================================================================================================")
		headerPrinted = true
	}

	fmt.Printf("| %-20s | %-13d | %-24s | %-24s | %-10s | %-12s | %-14d | %-12s | %-23s | %-28s | %-20s |\n",
		time.Now().Format("2006-01-02 15:04:05"), len(packet.Data()), src, dst, networkType,
		transportType, payloadSize, tcpFlags, appType, pidInfo, payloadSnippet)
}

func tcpFlagString(tcp *layers.TCP) string {
	flags := []string{}
	if tcp.SYN {
		flags = append(flags, "SYN")
	}
	if tcp.ACK {
		flags = append(flags, "ACK")
	}
	if tcp.FIN {
		flags = append(flags, "FIN")
	}
	if tcp.PSH {
		flags = append(flags, "PSH")
	}
	return strings.Join(flags, ",")
}

func safeSnippet(payload []byte) string {
	if len(payload) == 0 {
		return "-"
	}
	snippet := string(payload)
	cleaned := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || !unicode.IsPrint(r) {
			return '.'
		}
		return r
	}, snippet)
	if len(cleaned) > 20 {
		cleaned = cleaned[:20]
	}
	return cleaned
}

func loadPIDPortMapping() {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("netstat", "-ano")
	case "linux":
		cmd = exec.Command("ss", "-tulnp")
	case "darwin":
		cmd = exec.Command("lsof", "-i", "-P", "-n")
	default:
		fmt.Println("Неизвестная ОС, пропускаем анализ процессов.")
		return
	}

	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("Ошибка выполнения команды для PID маппинга: %v\n", err)
		return
	}

	tempMap := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if runtime.GOOS == "windows" {
			fields := strings.Fields(line)
			if len(fields) >= 5 && (strings.HasPrefix(fields[0], "TCP") || strings.HasPrefix(fields[0], "UDP")) {
				proto := strings.ToLower(fields[0])
				localAddr := fields[1]
				pid := fields[len(fields)-1]
				addrParts := strings.Split(localAddr, ":")
				if len(addrParts) >= 2 {
					port := addrParts[len(addrParts)-1]
					key := fmt.Sprintf("%s/%s", port, proto)
					tempMap[key] = pid
				}
			}
		}
	}
	mappingMutex.Lock()
	pidPortMap = tempMap
	mappingMutex.Unlock()
}

func lookupPID(port uint16, proto string) string {
	key := fmt.Sprintf("%d/%s", port, strings.ToLower(proto))
	mappingMutex.RLock()
	defer mappingMutex.RUnlock()
	if pid, ok := pidPortMap[key]; ok {
		return pid
	}
	return "-"
}

func loadPIDNameMapping() {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("tasklist", "/fo", "csv", "/nh")
	case "linux", "darwin":
		cmd = exec.Command("ps", "-e", "-o", "pid,comm")
	default:
		fmt.Println("Неизвестная ОС, пропускаем анализ имен процессов.")
		return
	}

	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("Ошибка выполнения команды для PID имен: %v\n", err)
		return
	}

	tempMap := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if runtime.GOOS == "windows" {
			fields := strings.Split(line, ",")
			if len(fields) >= 2 {
				name := strings.Trim(fields[0], "\"")
				pid := strings.Trim(fields[1], "\"")
				tempMap[pid] = name
			}
		} else {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				pid := fields[0]
				name := fields[1]
				tempMap[pid] = name
			}
		}
	}
	mappingMutex.Lock()
	pidNameMap = tempMap
	mappingMutex.Unlock()
}

func lookupProcessName(pid string) string {
	mappingMutex.RLock()
	defer mappingMutex.RUnlock()
	if name, ok := pidNameMap[pid]; ok {
		return fmt.Sprintf("%s(%s)", name, pid)
	}
	if pid != "-" {
		return fmt.Sprintf("Unknown(%s)", pid)
	}
	return "-"
}
