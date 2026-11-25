#!/usr/bin/env python3
"""
Uso:
    python3 reto2_puertos_servicios.py =>sencillo escnaea: scanme.nmap.org, puertos 1-1024. O 
    puedes escoger los puertos con: -p 20-100
    python3 reto2_puertos_servicios.py 192.168.1.10 -p 22,80,443
"""

import argparse
import sys

import nmap


def escanear_servicios(objetivo: str, puertos: str) -> nmap.PortScanner:
    nm = nmap.PortScanner()

    nm.scan(hosts=objetivo, ports=puertos, arguments="-sV --open")
    return nm


def mostrar_resultados(nm: nmap.PortScanner) -> None:
    if not nm.all_hosts():
        print("[-] No hubo resultados (host caído o sin puertos abiertos).")
        return

    for host in nm.all_hosts():
        print(f"Host: {host} ({nm[host].hostname() or 'sin nombre'}) - Estado: {nm[host].state()}")

        for proto in nm[host].all_protocols():
            print(f"  Protocolo: {proto}")
            print(f"  {'PUERTO':<8}{'ESTADO':<10}{'SERVICIO':<14}{'PRODUCTO':<20}VERSIÓN")
            print("  " + "-" * 70)

            for puerto in sorted(nm[host][proto].keys()):
                info = nm[host][proto][puerto]
                print(
                    f"  {puerto:<8}{info['state']:<10}{info['name']:<14}"
                    f"{info.get('product', '') or '-':<20}"
                    f"{info.get('version', '') or '-'}"
                )
        print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Puertos abiertos y versiones (nmap -sV)")
    parser.add_argument("objetivo", nargs="?", default="scanme.nmap.org")
    parser.add_argument("-p", "--puertos", default="1-1024", help="Ej: 22,80,443 o 1-1024")
    args = parser.parse_args()

    print(f"[*] Escaneando {args.objetivo} (puertos {args.puertos}) con -sV ...\n")

    try:
        nm = escanear_servicios(args.objetivo, args.puertos)
    except nmap.PortScannerError as e:
        print(f"[!] Error de Nmap: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error inesperado: {e}")
        sys.exit(1)

    mostrar_resultados(nm)
    print(f"[+] Comando ejecutado: {nm.command_line()}")


if __name__ == "__main__":
    main()

"""
Usé -sV porque pide a Nmap que interactúe con cada puerto abierto para identificar el servicio, el producto y su versión, 
y no solo el número de puerto. 
Añadí --open para mostrar solo puertos abiertos y limité el rango a 1-1024 por defecto para que el escaneo sea rápido 
y razonable con scanme.nmap.org. 
Separé el código en escanear_servicios() y mostrar_resultados(). 
Recorrí protocolo → puerto → información, que es como python-nmap organiza el diccionario, y usé .get() con valor por defecto 
porque product y version pueden venir vacíos.
"""