#!/usr/bin/env python3

import socket
import struct
import sys
import time
import select

ICMP_TIMEOUT = 3
MAX_HOPS = 30
DEST_PORT = 33434

def resolve_host(host):
    try:
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror:
        print("Error: не удалось разрешить доменное имя", host)
        sys.exit(1)

def get_as_number(ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("whois.cymru.com", 43))
        query = f"begin\nverbose\n{ip}\nend\n"
        s.sendall(query.encode())
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        s.close()
        lines = response.decode().splitlines()
        if len(lines) >= 2:
            parts = lines[1].split("|")
            as_number = parts[0].strip()
            return as_number
        else:
            return "Не определено"
    except Exception as e:
        return f"Ошибка: {e}"

def traceroute(dest_ip):
    hops = []
    print(f"Трассировка до {dest_ip} (до {MAX_HOPS} хопов):")
    for ttl in range(1, MAX_HOPS+1):
        try:
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            recv_sock.settimeout(ICMP_TIMEOUT)
            recv_sock.bind(("", DEST_PORT))
        except PermissionError:
            print("Ошибка: для работы с RAW-сокетами нужны права суперпользователя, нужно запустить скрипт через sudo.")
            sys.exit(1)
        except Exception as e:
            print(f"Ошибка при создании сокетов: {e}")
            sys.exit(1)

        try:
            send_sock.sendto(b"", (dest_ip, DEST_PORT))
            start_time = time.time()
            ready = select.select([recv_sock], [], [], ICMP_TIMEOUT)
            if ready[0] == []:
                print(f"{ttl:2d}  * * *")
                hops.append((ttl, "*", "Не определено"))
            else:
                recv_packet, addr = recv_sock.recvfrom(512)
                elapsed = (time.time() - start_time) * 1000
                curr_addr = addr[0]
                try:
                    host = socket.gethostbyaddr(curr_addr)[0]
                except socket.herror:
                    host = curr_addr
                as_number = get_as_number(curr_addr)
                print(f"{ttl:2d}  {curr_addr} ({host})  {int(elapsed)}ms  AS: {as_number}")
                hops.append((ttl, curr_addr, as_number))
                if curr_addr == dest_ip:
                    break
        except socket.timeout:
            print(f"{ttl:2d}  * * *")
            hops.append((ttl, "*", "Не определено"))
        except Exception as e:
            print(f"{ttl:2d}  Ошибка: {e}")
            hops.append((ttl, "Ошибка", "Ошибка"))
        finally:
            send_sock.close()
            recv_sock.close()
    return hops

def main():
    if len(sys.argv) != 2:
        print("Usage: sudo python3 traceroute.py <домен или IP>")
        sys.exit(1)
    target = sys.argv[1]
    dest_ip = resolve_host(target)
    print(f"Целевой IP: {dest_ip}")
    hops = traceroute(dest_ip)
    print("\nИтоговая таблица:")
    print("No\tIP\t\tAS")
    for hop in hops:
        print(f"{hop[0]}\t{hop[1]}\t{hop[2]}")

if __name__ == "__main__":
    main()
