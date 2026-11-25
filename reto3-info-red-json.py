#!/usr/bin/env python3
"""
Uso:
    python3 reto3_info_red_json.py                                => sin parametros: scanme.nmap.org
    python3 reto3_info_red_json.py 192.168.1.10 -o resultado.json =>otorgando parametros
"""

import argparse
import json
import os
import sys
from datetime import datetime

import nmap


def es_admin() -> bool:
    if hasattr(os, "geteuid"):  # Linux / macOS
        return os.geteuid() == 0
    try:  # Windows
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def escanear(objetivo: str, puertos: str) -> nmap.PortScanner:
    nm = nmap.PortScanner()

    args = "-sV --script=banner,http-title --open"

    if es_admin():
        args += " -O"  # detetca SO
    else:
        print("[!] Sin privilegios de administrador: se omite -O (detección de SO).")

    nm.scan(hosts=objetivo, ports=puertos, arguments=args)
    return nm


def construir_diccionario(nm: nmap.PortScanner, objetivo: str) -> dict:
    """Convierte el resultado de nmap en un diccionario limpio y serializable."""
    resultado = {
        "objetivo": objetivo,
        "fecha_escaneo": datetime.now().isoformat(timespec="seconds"),
        "comando": nm.command_line(),
        "hosts": [],
    }

    for host in nm.all_hosts():
        datos_host = {
            "ip": host,
            "hostname": nm[host].hostname() or None,
            "estado": nm[host].state(),
            "sistema_operativo": [],
            "puertos": [],
        }

        # Coincidencias de SO (solo existen si se ejecutó -O)
        for coincidencia in nm[host].get("osmatch", []):
            datos_host["sistema_operativo"].append(
                {"nombre": coincidencia["name"], "precision": coincidencia["accuracy"]}
            )

        # Puertos, servicios y salida de scripts NSE
        for proto in nm[host].all_protocols():
            for puerto in sorted(nm[host][proto].keys()):
                info = nm[host][proto][puerto]
                datos_host["puertos"].append(
                    {
                        "puerto": puerto,
                        "protocolo": proto,
                        "estado": info["state"],
                        "servicio": info["name"],
                        "producto": info.get("product") or None,
                        "version": info.get("version") or None,
                        "scripts_nse": info.get("script", {}),
                    }
                )

        resultado["hosts"].append(datos_host)

    return resultado


def main() -> None:
    parser = argparse.ArgumentParser(description="Info de red a JSON (SO + NSE)")
    parser.add_argument("objetivo", nargs="?", default="scanme.nmap.org")
    parser.add_argument("-p", "--puertos", default="1-1024")
    parser.add_argument("-o", "--salida", default="resultado_reto3.json")
    args = parser.parse_args()

    print(f"[*] Escaneando {args.objetivo} ...\n")

    try:
        nm = escanear(args.objetivo, args.puertos)
    except nmap.PortScannerError as e:
        print(f"[!] Error de Nmap: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error inesperado: {e}")
        sys.exit(1)

    datos = construir_diccionario(nm, args.objetivo)

    with open(args.salida, "w", encoding="utf-8") as f:
        json.dump(datos, f, indent=4, ensure_ascii=False)

    print(json.dumps(datos, indent=4, ensure_ascii=False))
    print(f"\n[+] Resultados guardados en: {args.salida}")


if __name__ == "__main__":
    main()