# Basic Port Scanner created by Raymond Zhang
# Supports TCP & UDP

import asyncio
import socket
import time
import argparse
import sys
import json
import csv

def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except:
        return "unknown"

async def scan_port(target, port, timeout, sem):
    async with sem:
        try:
            conn = asyncio.open_connection(target, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            try:
                banner = await asyncio.wait_for(reader.read(100), timeout=0.2)
                banner = banner.decode(errors="ignore").strip()
            except:
                banner = ""
            writer.close()
            await writer.wait_closed()
            return (port, banner)
        except:
            return None

async def scan_range_async(target, start_port, end_port, concurrency=500, timeout=0.3):
    sem = asyncio.Semaphore(concurrency)
    tasks = []
    for port in range(start_port, end_port + 1):
        tasks.append(scan_port(target, port, timeout, sem))
    results = await asyncio.gather(*tasks)
    return [item for item in results if item is not None]

# TCP

async def scan_udp_port(target, port, timeout=1.0):
    try:
        def udp_probe():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            try:
                sock.sendto(b"\x00", (target, port))
                data, _ = sock.recvfrom(1024)
                return (port, data.decode(errors="ignore").strip())
            except socket.timeout:
                return (port, "") 
            except Exception:
                return None
            finally:
                sock.close()

        return await asyncio.to_thread(udp_probe)

    except:
        return None
    
async def scan_udp_range(target, start_port, end_port):
    tasks = []
    for port in range(start_port, end_port + 1):
        tasks.append(scan_udp_port(target, port))
    results = await asyncio.gather(*tasks)
    return [item for item in results if item is not None]

# UDP

def validate_inputs(target, start_port, end_port):
    if not target:
        print("Error: Target cannot be empty.")
        sys.exit(1)
    if not isinstance(start_port, int) or not isinstance(end_port, int):
        print("Error: Ports must be integers.")
        sys.exit(1)
    if start_port < 1 or end_port > 65535:
        print("Error: Ports must be between 1 and 65535.")
        sys.exit(1)
    if start_port > end_port:
        print("Error: Start port cannot be greater than end port.")
        sys.exit(1)
    try:
        socket.gethostbyname(target)
    except socket.gaierror:
        print("Error: Unable to resolve target hostname or IP.")
        sys.exit(1)

def save_results(results, filepath, fmt):
    data = []
    for port, banner in results:
        data.append({
            "port": port,
            "service": get_service_name(port),
            "banner": banner
        })

    if fmt == "json":
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

    elif fmt == "csv":
        with open(filepath, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["port", "service", "banner"])
            writer.writeheader()
            writer.writerows(data)

    elif fmt == "txt":
        with open(filepath, "w") as f:
            for entry in data:
                line = f"{entry['port']} ({entry['service']})"
                if entry["banner"]:
                    line += f" | {entry['banner']}"
                f.write(line + "\n")

def main():
    parser = argparse.ArgumentParser(description="Basic Port Scanner by Raymond Zhang")
    parser.add_argument("--target", help="Target IP address or domain")
    parser.add_argument("--start", type=int, help="Starting port")
    parser.add_argument("--end", type=int, help="Ending port")
    parser.add_argument("--output", help="Output file path (e.g., results.json)")
    parser.add_argument("--format", choices=["txt", "json", "csv"], help="Output format")
    parser.add_argument("--udp", action="store_true", help="Enable UDP scanning")
    args = parser.parse_args()
    target = args.target or input("Enter the target IP address or domain: ")
    start_port = args.start if args.start is not None else int(input("Enter the starting port for the scan: "))
    end_port = args.end if args.end is not None else int(input("Enter the ending port for the scan: "))
    validate_inputs(target, start_port, end_port)
    print(f"\nScanning {target} from port {start_port} to {end_port}...\n")
    start_time = time.time()
    open_ports = []
    udp_results = []
    if args.udp:
        udp_results = asyncio.run(scan_udp_range(target, start_port, end_port))
        udp_results.sort(key=lambda x: x[0])
        if udp_results:
            print("UDP results:")
            for port, banner in udp_results:
                service = get_service_name(port)
                if banner:
                    print(f"  {port:<6} ({service})  |  {banner}")
                else:
                    print(f"  {port:<6} ({service})")
        else:
            print("No UDP responses received.")
    else:
        open_ports = asyncio.run(scan_range_async(target, start_port, end_port))
        open_ports.sort(key=lambda x: x[0])
        if open_ports:
            print("TCP results:")
            for port, banner in open_ports:
                service = get_service_name(port)
                if banner:
                    print(f"  {port:<6} ({service})  |  {banner}")
                else:
                    print(f"  {port:<6} ({service})")
        else:
            print("No open TCP ports found.")
    if args.output and args.format:
        if args.udp:
            save_results(udp_results, args.output, args.format)
        else:
            save_results(open_ports, args.output, args.format)
        print(f"\nResults saved to {args.output}")
    duration = time.time() - start_time
    print(f"\nScan completed in {duration:.2f} seconds.")

if __name__ == "__main__":
    main()
