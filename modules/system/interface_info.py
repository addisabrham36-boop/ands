from core.module_base import ModuleBase
import psutil
import socket


class InterfaceInfo(ModuleBase):
    """
    Network Hardware & Interface Diagnostic Sentinel.
    Inspects available NIC adapters, IP addresses, netmasks, broadcast addresses,
    MTU, duplex modes, and byte transmission throughput.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {}

    def run(self):
        print("\n[*] Host Network Interfaces & Diagnostic Report:\n")
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        io_counters = psutil.net_io_counters(pernic=True)

        print(f"{'Interface':<14}{'Status':<8}{'IP Address':<18}{'MTU':<8}{'Duplex':<10}{'Speed (Mbps)':<12}{'RX (MB)':<10}{'TX (MB)':<10}")
        print("-" * 92)

        for iface, addr_list in addrs.items():
            ipv4 = "N/A"
            for a in addr_list:
                if a.family == socket.AF_INET:
                    ipv4 = a.address
                    break

            stat = stats.get(iface)
            is_up = "UP" if (stat and stat.isup) else "DOWN"
            mtu = stat.mtu if stat else "N/A"
            speed = stat.speed if stat else "N/A"
            duplex = str(stat.duplex).split(".")[-1] if stat else "N/A"

            io = io_counters.get(iface)
            rx_mb = round(io.bytes_recv / (1024 * 1024), 1) if io else 0.0
            tx_mb = round(io.bytes_sent / (1024 * 1024), 1) if io else 0.0

            print(f"{iface:<14}{is_up:<8}{ipv4:<18}{str(mtu):<8}{duplex:<10}{str(speed):<12}{rx_mb:<10}{tx_mb:<10}")

        print("-" * 92 + "\n")
