import ipaddress

def classify_ipv4(ip_str):
    """
    Phân loại địa chỉ IPv4.

    Args:
        ip_str: Chuỗi địa chỉ IPv4.

    Returns:
        Loại địa chỉ IPv4.
    """
    try:
        ip = ipaddress.ip_address(ip_str)

        if ip == ipaddress.ip_address('0.0.0.0'):
            return "Unspecified Address"
        elif ip == ipaddress.ip_address('255.255.255.255'):
            return "Broadcast Address"
        elif ip in ipaddress.ip_network('10.0.0.0/8'):
            return "Private IP (10.0.0.0/8)"
        elif ip in ipaddress.ip_network('172.16.0.0/12'):
            return "Private IP (172.16.0.0/12)"
        elif ip in ipaddress.ip_network('192.168.0.0/16'):
            return "Private IP (192.168.0.0/16)"
        elif ip in ipaddress.ip_network('127.0.0.0/8'):
            return "Loopback IP"
        elif ip in ipaddress.ip_network('224.0.0.0/4'):
            return "Multicast"
        else:
            return "Public IP"
    except ValueError:
        return "Invalid IPv4 Address"


def classify_ipv6(ip_str):
    """
    Phân loại địa chỉ IPv6.

    Args:
        ip_str: Chuỗi địa chỉ IPv6.

    Returns:
        Loại địa chỉ IPv6.
    """
    try:
        ip = ipaddress.ip_address(ip_str)

        if ip == ipaddress.ip_address('::'):
            return "Unspecified Address"
        elif ip == ipaddress.ip_address('::1'):
            return "Loopback IP"
        elif ip == ipaddress.ip_address('ff02::1'):
            return "Link-Local All-Nodes Multicast"
        elif ip == ipaddress.ip_address('ff02::2'):
            return "Link-Local All-Routers Multicast"
        elif ip in ipaddress.ip_network('fc00::/7'):
            return "Unique Local Address (ULA)"
        elif ip in ipaddress.ip_network('fe80::/10'):
            return "Link-Local Address"
        elif ip in ipaddress.ip_network('ff00::/8'):
            return "Multicast"
        elif ip in ipaddress.ip_network('2001:0000::/32'):
            return "Teredo Address"
        elif ip in ipaddress.ip_network('::ffff:0:0/96'):
            return "IPv4-Mapped Address"
        elif ip in ipaddress.ip_network('2001:0002::/48'):
            return "Benchmarking Address"
        elif ip in ipaddress.ip_network('2001:0010::/28'):
            return "Orchid Address"
        elif ip in ipaddress.ip_network('2002::/16'):
            return "6to4 Address"
        elif ip in ipaddress.ip_network('2001:db8::/32'):
            return "Documentation Address"
        elif ip in ipaddress.ip_network('2000::/3'):
            return "Global Unicast Address"
        else:
            return "Other IPv6 Address"
    except ValueError:
        return "Invalid IPv6 Address"

def main():
    ip_address = input("Enter an IP address: ")

    try:
        ip = ipaddress.ip_address(ip_address)
        if ip.version == 4:
            print(f"IPv4 Address Type: {classify_ipv4(ip_address)}")
        elif ip.version == 6:
            print(f"IPv6 Address Type: {classify_ipv6(ip_address)}")
        else:
            print("Invalid IP Address")
    except ValueError:
        print("Invalid IP Address")

if __name__ == "__main__":
    main()