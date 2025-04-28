package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/google/gopacket/pcap"
	"github.com/mercenery/go-sniffer/internal/capture"
)

func main() {
	fmt.Println("Go Sniffer запущен 🚀")

	// Получаем список всех интерфейсов
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Не удалось получить список интерфейсов: %v", err)
	}

	// Если интерфейсов нет
	if len(interfaces) == 0 {
		log.Fatal("Нет доступных сетевых интерфейсов для захвата.")
	}

	// Выводим интерфейсы
	fmt.Println("\nДоступные сетевые интерфейсы:")
	for i, device := range interfaces {
		fmt.Printf("[%d] Имя: %s", i, device.Name)
		if len(device.Description) > 0 {
			fmt.Printf(" — %s", device.Description)
		}
		fmt.Println()
	}

	// Просим выбрать интерфейс
	fmt.Print("\nВведите номер интерфейса для захвата: ")

	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	index, err := strconv.Atoi(input)
	if err != nil || index < 0 || index >= len(interfaces) {
		log.Fatalf("Неверный номер интерфейса: %v", input)
	}

	deviceName := interfaces[index].Name
	fmt.Printf("\nВыбран интерфейс: %s\n", deviceName)

	// Запускаем захват пакетов
	capture.CapturePackets(deviceName)
}
