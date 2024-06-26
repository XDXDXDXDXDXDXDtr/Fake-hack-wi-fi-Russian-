import random
import string
import time
import os
from scapy.all import sniff, Dot11
import pyfiglet

# Функция для очистки экрана
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# Функция для отображения заголовка
def display_title():
    print("\033[1;32m" + pyfiglet.figlet_format("SUMIG") + "\033[0m")

# Функция для отображения меню
def display_menu():
    print("1) Взлом по Wi-Fi")
    print("\n" * 2)

# Функция для сканирования доступных сетей
def scan_networks(interface="wlan0"):
    networks = set()
    def callback(packet):
        if packet.haslayer(Dot11):
            if packet.type == 0 and packet.subtype == 8:  # Beacon frame
                ssid = packet.info.decode('utf-8')
                bssid = packet.addr2
                networks.add((ssid, bssid))
                if len(networks) >= 20:
                    return False

    sniff(iface=interface, prn=callback, timeout=10)
    return list(networks)

# Функция для отображения доступных сетей
def display_networks(networks):
    for idx, (ssid, bssid) in enumerate(networks):
        print(f"{idx + 1}. {ssid} ({bssid})")

# Функция для имитации процесса взлома
def hacking_process(network):
    clear_screen()
    display_title()
    print(f"Взлом {network[0]} ({network[1]}) начался...")
    for i in range(100):
        random_string = ''.join(random.choices(string.ascii_uppercase + string.digits + string.punctuation, k=10))
        figlet_text = pyfiglet.figlet_format(random_string)
        clear_screen()
        display_title()
        print(figlet_text)
        print(f"Взлом идет: ({i + 1}%)", flush=True)
        time.sleep(0.1)
    print("\nВзлом завершен!")

# Основная функция
def main():
    while True:
        clear_screen()
        display_title()
        display_menu()
        choice = input("Выберите опцию: ")
        if choice == '1':
            clear_screen()
            display_title()
            print("Сканирование доступных сетей...")
            networks = scan_networks()
            clear_screen()
            display_title()
            display_networks(networks)
            selected_index = int(input("\nВыберите сеть (1-20): ")) - 1
            if 0 <= selected_index < len(networks):
                hacking_process(networks[selected_index])
            else:
                print("Неверный выбор сети. Попробуйте снова.")
        else:
            print("Неверный выбор. Попробуйте снова.")
        input("\nНажмите Enter для продолжения...")

if __name__ == "__main__":
    main()
