import tkinter as tk
from tkinter import messagebox
import ipaddress


def classify_ipv4(ip_str):
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


def calculate_ipv4_details(ip_with_cidr):
    try:
        network = ipaddress.ip_network(ip_with_cidr, strict=False)
        network_address = network.network_address
        broadcast_address = network.broadcast_address
        hosts = list(network.hosts())
        first_host = hosts[0] if hosts else None
        last_host = hosts[-1] if hosts else None
        return network_address, broadcast_address, first_host, last_host
    except ValueError:
        return None, None, None, None


def classify_ip():
    ip_str = ip_entry.get().strip()  # Lấy địa chỉ IP từ ô nhập liệu
    if not ip_str:
        messagebox.showerror("Error", "Please enter an IP address.")
        return

    try:
        # Phân loại địa chỉ IP
        ip = ipaddress.ip_address(ip_str)
        if ip.version == 4:
            result = f"IPv4 Address Type: {classify_ipv4(ip_str)}"
            # Tính toán địa chỉ mạng
            cidr = cidr_entry.get().strip()  # Lấy subnet mask (CIDR) từ ô nhập
            if cidr:
                try:
                    ip_with_cidr = f"{ip_str}/{cidr}"
                    network_address, broadcast_address, first_host, last_host = calculate_ipv4_details(ip_with_cidr)
                    result += (
                        f"\n\nNetwork Address: {network_address}\n"
                        f"Broadcast Address: {broadcast_address}\n"
                        f"Host Range: {first_host} - {last_host}"
                    )
                except ValueError:
                    result += "\n\nInvalid CIDR Subnet Mask"
        elif ip.version == 6:
            result = f"IPv6 Address Type: {classify_ipv6(ip_str)}"
        else:
            result = "Unknown IP Address Type"
    except ValueError:
        result = "Invalid IP Address"

    # Hiển thị kết quả trong giao diện
    result_label.config(text=result)


def classify_ipv6(ip_str):
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


# Giao diện Tkinter
root = tk.Tk()
root.title("IP Address Classifier")
root.geometry("600x400")
root.resizable(False, False)

# Nhãn tiêu đề
title_label = tk.Label(root, text="IP Address Classifier", font=("Arial", 16))
title_label.pack(pady=10)

# Nhập địa chỉ IP
ip_entry_label = tk.Label(root, text="Enter an IP Address:")
ip_entry_label.pack(pady=5)
ip_entry = tk.Entry(root, width=40, font=("Arial", 12))
ip_entry.pack(pady=5)

# Nhập CIDR Subnet Mask
cidr_label = tk.Label(root, text="Enter Subnet Mask (CIDR) (Optional):")
cidr_label.pack(pady=5)
cidr_entry = tk.Entry(root, width=40, font=("Arial", 12))
cidr_entry.pack(pady=5)

# Nút kiểm tra
classify_button = tk.Button(root, text="Classify IP", command=classify_ip, font=("Arial", 12), bg="blue", fg="white")
classify_button.pack(pady=10)

# Nhãn hiển thị kết quả
result_label = tk.Label(root, text="", font=("Arial", 12), fg="green", wraplength=580, justify="left")
result_label.pack(pady=20)

# Chạy giao diện
root.mainloop()