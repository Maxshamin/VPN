import socket
import os
import configparser
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Функция для чтения конфигурационного файла
def load_config():
    config = configparser.ConfigParser()
    config.read('config.ini')
    return config


# Обработка UDP трафика
def handle_udp_packet(packet):
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    remote_socket.sendto(packet.payload, (packet.dst_addr, packet.dst_port))
    response, _ = remote_socket.recvfrom(4096)
    return response


# Обработка TCP трафика
def handle_tcp_packet(packet):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as remote_socket:
        remote_socket.connect((packet.dst_addr, packet.dst_port))
        remote_socket.sendall(packet.payload)
        response = remote_socket.recv(4096)
    return response


def start_server():
    config = load_config()

    # Данные для подключения из конфигурационного файла
    host = config['VPN']['server_ip']
    port = int(config['VPN']['server_port'])
    aes_key = config['Encryption']['aes_key'].encode()  # Читаем AES ключ из конфигурации

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f'Server listening on {host}:{port}...')

    conn, addr = server_socket.accept()
    print(f'Connection established with {addr}')

    while True:
        # Получаем данные и разбираем IV
        data = conn.recv(4096)
        if not data:
            break
        iv = data[:16]
        encrypted_payload = data[16:]

        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))

        # Дешифруем полезную нагрузку
        decryptor = cipher.decryptor()
        payload = decryptor.update(encrypted_payload) + decryptor.finalize()

        # Здесь нужно реализовать обработку пакетов (TCP/UDP/ICMP)
        # Например:
        response = handle_tcp_packet(payload)  # Обрабатываем как TCP

        # Шифруем и отправляем ответ клиенту
        encryptor = cipher.encryptor()
        encrypted_response = encryptor.update(response) + encryptor.finalize()
        conn.sendall(iv + encrypted_response)

    conn.close()


if __name__ == "__main__":
    start_server()

