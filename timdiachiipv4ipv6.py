import tkinter as tk
from tkinter import messagebox
import ipaddress


def classify_ipv4(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)

        if ip == ipaddress.ip_address('0.0.0.0'):
            return "Unspecified Address", "Dùng để chỉ địa chỉ không xác định trong mạng.", "Không thể giao tiếp."
        elif ip == ipaddress.ip_address('255.255.255.255'):
            return "Broadcast Address", "Dùng để gửi gói tin đến tất cả các thiết bị trong mạng.", "Không thể gán cho thiết bị cụ thể."
        elif ip in ipaddress.ip_network('10.0.0.0/8'):
            return "Private IP (10.0.0.0/8)", "Dùng cho mạng nội bộ (LAN).", "Không thể truy cập trực tiếp từ Internet."
        elif ip in ipaddress.ip_network('172.16.0.0/12'):
            return "Private IP (172.16.0.0/12)", "Dùng cho mạng nội bộ (LAN).", "Không thể truy cập trực tiếp từ Internet."
        elif ip in ipaddress.ip_network('192.168.0.0/16'):
            return "Private IP (192.168.0.0/16)", "Dùng cho mạng nội bộ (LAN).", "Không thể truy cập trực tiếp từ Internet."
        elif ip in ipaddress.ip_network('127.0.0.0/8'):
            return "Loopback IP", "Dùng để kiểm tra kết nối trên chính máy tính.", "Không thể giao tiếp qua mạng."
        elif ip in ipaddress.ip_network('224.0.0.0/4'):
            return "Multicast", "Dùng để gửi gói tin đến nhóm thiết bị cụ thể.", "Không được sử dụng để liên lạc thông thường."
        else:
            return "Public IP", "Dùng để giao tiếp trên Internet.", "Yêu cầu bảo mật cao hơn để tránh bị tấn công."
    except ValueError:
        return "Invalid IPv4 Address", "Địa chỉ không hợp lệ.", "Không thể sử dụng."


def calculate_ipv4_details(ip_with_cidr):
    """
    Tính toán các thông tin của IPv4 với subnet mask (CIDR).
    """
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
    ip_str = ip_entry.get().strip()
    cidr = cidr_entry.get().strip()

    if not ip_str:
        messagebox.showerror("Error", "Please enter an IP address.")
        return

    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.version == 4:
            ip_type, purpose, drawback = classify_ipv4(ip_str)

            # Tính toán với CIDR nếu được cung cấp
            if cidr:
                try:
                    ip_with_cidr = f"{ip_str}/{cidr}"
                    network_address, broadcast_address, first_host, last_host = calculate_ipv4_details(ip_with_cidr)
                    result = (
                        f"IP Type: {ip_type}\n"
                        f"Purpose: {purpose}\n"
                        f"Drawback: {drawback}\n\n"
                        f"Subnet Mask: /{cidr}\n"
                        f"Network Address: {network_address}\n"
                        f"Broadcast Address: {broadcast_address}\n"
                        f"Host Range: {first_host} - {last_host}"
                    )
                except ValueError:
                    result = (
                        f"IP Type: {ip_type}\n"
                        f"Purpose: {purpose}\n"
                        f"Drawback: {drawback}\n\n"
                        f"Invalid Subnet Mask (CIDR) provided."
                    )
            else:
                result = (
                    f"IP Type: {ip_type}\n"
                    f"Purpose: {purpose}\n"
                    f"Drawback: {drawback}\n\n"
                    f"Subnet Mask: Not provided."
                )
        else:
            result = "Only IPv4 classification with Subnet Mask is supported in this version."

    except ValueError:
        result = "Invalid IP Address. Please enter a valid IPv4 or IPv6 address."

    # Hiển thị kết quả
    result_label.config(text=result)


# Giao diện Tkinter
root = tk.Tk()
root.title("IP Address Classifier with Subnet Mask")
root.geometry("600x500")
root.resizable(False, False)

# Nhãn tiêu đề
title_label = tk.Label(root, text="IP Address Classifier with Subnet Mask", font=("Arial", 16))
title_label.pack(pady=10)

# Nhập địa chỉ IP
ip_entry_label = tk.Label(root, text="Enter an IP Address:")
ip_entry_label.pack(pady=5)
ip_entry = tk.Entry(root, width=40, font=("Arial", 12))
ip_entry.pack(pady=5)

# Nhập CIDR Subnet Mask
cidr_label = tk.Label(root, text="Enter Subnet Mask (CIDR) (e.g., 24):")
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