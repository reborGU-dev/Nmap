#!/usr/bin/env python3
"""
Uso:
    python3 reto1_descubrir_hosts.py                            => scanme.nmap.org
    python3 reto1_descubrir_hosts.py 192.168.100.0/24           => red local, 3 pasadas
    python3 reto1_descubrir_hosts.py 192.168.100.0/24 -n 5      => 5 pasadas

Importante:
    Ejecutar como Administrador.
"""

import argparse
import ipaddress
import os
import sys

import nmap


def es_admin() -> bool:
    """True si el script corre con privilegios elevados."""
    if hasattr(os, "geteuid"):  # Linux / macOS
        return os.geteuid() == 0
    try:  # Windows
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def una_pasada(objetivo: str) -> dict[str, dict]:
    nm = nmap.PortScanner()


    nm.scan(hosts=objetivo, arguments="-sn -R")

    encontrados = {}
    for host in nm.all_hosts():
        if nm[host].state() != "up":
            continue

        mac = nm[host]["addresses"].get("mac", "-")
        fabricante = nm[host]["vendor"].get(mac, "Desconocido") if mac != "-" else "-"

        encontrados[host] = {
            "ip": host,
            "hostname": nm[host].hostname() or "(sin nombre)",
            "mac": mac,
            "fabricante": fabricante,
            "metodo": nm[host]["status"].get("reason", "-"),
            "apariciones": 1,
        }
    return encontrados


def descubrir_hosts(objetivo: str, pasadas: int) -> list[dict]:
    acumulado: dict[str, dict] = {}

    for n in range(1, pasadas + 1):
        resultado = una_pasada(objetivo)
        print(f"    Pasada {n}/{pasadas}: {len(resultado)} hosts")
        for ip, datos in resultado.items():
            if ip in acumulado:
                acumulado[ip]["apariciones"] += 1
            else:
                acumulado[ip] = datos

    return sorted(acumulado.values(), key=lambda h: ipaddress.ip_address(h["ip"]))


def main() -> None:
    parser = argparse.ArgumentParser(description="Descubrimiento de hosts activos (nmap -sn)")
    parser.add_argument("objetivo", nargs="?", default="scanme.nmap.org",
                        help="IP, rango o red CIDR (por defecto: scanme.nmap.org)")
    parser.add_argument("-n", "--pasadas", type=int, default=3,
                        help="Número de escaneos a combinar (por defecto: 3)")
    args = parser.parse_args()

    if not es_admin():
        print("[!] Sin privilegios de administrador: Nmap no usará ARP y puede omitir hosts.\n")

    print(f"[*] Escaneando {args.objetivo} con -sn ...\n")

    try:
        hosts = descubrir_hosts(args.objetivo, max(1, args.pasadas))
    except nmap.PortScannerError as e:
        print(f"[!] Error de Nmap: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error inesperado: {e}")
        sys.exit(1)

    if not hosts:
        print("\n[-] No se encontraron hosts activos.")
        return

    print(f"\n{'IP':<17}{'MAC':<19}{'FABRICANTE':<24}{'MÉTODO':<14}{'VISTO':<7}HOSTNAME")
    print("-" * 95)
    for h in hosts:
        visto = f"{h['apariciones']}/{args.pasadas}"
        print(f"{h['ip']:<17}{h['mac']:<19}{h['fabricante']:<24}{h['metodo']:<14}{visto:<7}{h['hostname']}")

    print(f"\n[+] Total de hosts activos (unión de {args.pasadas} pasadas): {len(hosts)}")


if __name__ == "__main__":
    main()