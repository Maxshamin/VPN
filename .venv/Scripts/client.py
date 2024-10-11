import socket
import pydivert
import configparser
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Функция для чтения конфигурационного файла
def load_config():
    config = configparser.ConfigParser()
    config.read('config.ini')
    return config

def start_client():
    config = load_config()

    # Данные для подключения из конфигурационного файла
    server_ip = config['VPN']['server_ip']
    server_port = int(config['VPN']['server_port'])
    aes_key = config['Encryption']['aes_key'].encode()  # Читаем ключ AES

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))
    print(f'Connected to VPN server {server_ip}:{server_port}')

    iv = os.urandom(16)  # Случайный вектор инициализации
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))

    with pydivert.WinDivert("true") as w:
        for packet in w:
            if packet.is_outbound and packet.payload:
                print(f"Intercepted packet: {packet.src_addr} -> {packet.dst_addr}")

                # Шифруем полезную нагрузку
                encryptor = cipher.encryptor()
                encrypted_payload = encryptor.update(packet.payload) + encryptor.finalize()

                # Отправляем зашифрованный трафик на сервер
                client_socket.sendall(iv + encrypted_payload)

                # Получаем и расшифровываем ответ
                encrypted_response = client_socket.recv(4096)
                decryptor = cipher.decryptor()
                packet.payload = decryptor.update(encrypted_response) + decryptor.finalize()

                w.send(packet)

    client_socket.close()

if __name__ == "__main__":
    start_client()

