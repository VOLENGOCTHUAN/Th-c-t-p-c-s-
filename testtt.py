import tkinter as tk
from tkinter import messagebox

class IPAddress:
    def __init__(self, ip_with_cidr):
        self.ip_with_cidr = ip_with_cidr

    def classify(self):
        raise NotImplementedError("Subclasses must implement classify method")

    def get_details(self):
        return {}

class IPv4Address(IPAddress):
    def __init__(self, ip_with_cidr):
        super().__init__(ip_with_cidr)
        try:
            self.ip_str, self.cidr_str = ip_with_cidr.split('/')
            self.ip_parts = list(map(int, self.ip_str.split('.')))
            self.cidr = int(self.cidr_str)
        except ValueError:
            raise ValueError("Định dạng IPv4 không hợp lệ. Đúng định dạng là A.B.C.D/Prefix.")

        # Kiểm tra số lượng block và giá trị từng block
        if len(self.ip_parts) != 4 or not all(0 <= part <= 255 for part in self.ip_parts):
            raise ValueError("IPv4 phải có đúng 4 block với giá trị từ 0 đến 255.")

        # Kiểm tra prefix (CIDR)
        if not (0 <= self.cidr <= 32):
            raise ValueError("Prefix CIDR của IPv4 phải nằm trong khoảng từ 0 đến 32.")


    def classify(self):
        ip_parts = self.ip_parts
        if ip_parts == [0, 0, 0, 0]:
            return "Unspecified Address: Chủ yếu sử dụng làm địa chỉ nguồn khi thiết bị khởi động và chưa có địa chỉ IP cụ thể."
        elif ip_parts == [255, 255, 255, 255]:
            return "Broadcast Address: Được sử dụng để gửi dữ liệu tới tất cả các thiết bị trên mạng con và không cấp phát cho thiết bị."
        elif 1 <= ip_parts[0] <= 126:
            return "Class A(Public IP): Dải địa chỉ từ 1.0.0.0 đến 126.0.0.0. Thường được sử dụng cho các mạng lớn."
        elif ip_parts[0] == 127:
            return "Loopback IP: Địa chỉ mạng nội bộ để kiểm tra thiết bị, dải từ 127.0.0.0 đến 127.255.255.255."
        elif 128 <= ip_parts[0] <= 191:
            return "Class B(Public IP): Dải địa chỉ từ 128.0.0.0 đến 191.255.0.0. Thường được sử dụng cho các mạng vừa và nhỏ."
        elif 192 <= ip_parts[0] <= 223:
            return "Class C(Public IP): Dải địa chỉ từ 192.0.0.0 đến 223.255.255.0. Thường được sử dụng cho các mạng nhỏ."
        elif 224 <= ip_parts[0] <= 239:
            return "Class D: Dải địa chỉ từ 224.0.0.0 đến 239.255.255.255. Được sử dụng cho Multicast."
        elif 240 <= ip_parts[0] <= 255:
            return "Class E(Public IP): Dải địa chỉ từ 240.0.0.0 trở đi. Được dành riêng cho nghiên cứu hoặc sử dụng trong tương lai."
        elif 10 == ip_parts[0]:
            return "Private IP (10.0.0.0/8): Địa chỉ IP trong mạng nội bộ, không thể truy cập trực tiếp từ Internet."
        elif ip_parts[0] == 172 and 16 <= ip_parts[1] <= 31:
            return "Private IP (172.16.0.0/12): Địa chỉ IP trong mạng nội bộ, không thể truy cập trực tiếp từ Internet."
        elif ip_parts[0] == 192 and ip_parts[1] == 168:
            return "Private IP (192.168.0.0/16): Địa chỉ IP trong mạng nội bộ, thường sử dụng trong mạng gia đình hoặc văn phòng."
        elif ip_parts[0] == 127:
            return "Loopback IP: Được sử dụng để kiểm tra nội bộ trên thiết bị và không bao giờ truyền qua mạng."
        elif ip_parts[0] == 169 and ip_parts[1] == 254:
            return "Link-Local Address: Tự động cấp phát khi không có máy chủ DHCP, chỉ hoạt động trong mạng cục bộ."
        elif 224 <= ip_parts[0] <= 239:
            return "Multicast: Được sử dụng để gửi dữ liệu đến nhiều thiết bị trong một nhóm trên mạng."
        elif 198 == ip_parts[0] and 18 <= ip_parts[1] <= 19:
            return "Benchmarking IP (198.18.0.0/15): Được sử dụng để kiểm tra hiệu năng mạng."
        elif ip_parts[0] == 192 and ip_parts[1] == 88 and ip_parts[2] == 99:
            return "6to4 Relay Address (192.88.99.0/24): Hỗ trợ chuyển đổi giữa IPv4 và IPv6."
        elif ip_parts[0] == 192 and ip_parts[1] == 0 and ip_parts[2] == 2:
            return "Documentation Address (192.0.2.0/24): Được sử dụng trong tài liệu kỹ thuật và ví dụ, không dùng trên mạng thực tế."
        elif ip_parts[0] == 198 and ip_parts[1] == 51 and ip_parts[2] == 100:
            return "Documentation Address (198.51.100.0/24): Được sử dụng trong tài liệu kỹ thuật và ví dụ, không dùng trên mạng thực tế."
        elif ip_parts[0] == 203 and ip_parts[1] == 0 and ip_parts[2] == 113:
            return "Documentation Address (203.0.113.0/24): Được sử dụng trong tài liệu kỹ thuật và ví dụ, không dùng trên mạng thực tế."
        else:
            return "Public IP: Địa chỉ IP công cộng, được cấp phát để truy cập Internet."


    def get_details(self):
        # ... (rest of IPv4 get_details remains the same)
        binary_ip = ''.join([format(part, '08b') for part in self.ip_parts])
        mask = '1' * self.cidr + '0' * (32 - self.cidr)
        network_binary = ''.join([binary_ip[i] if mask[i] == '1' else '0' for i in range(32)])
        broadcast_binary = ''.join([binary_ip[i] if mask[i] == '1' else '1' for i in range(32)])

        network_address = '.'.join([str(int(network_binary[i:i+8], 2)) for i in range(0, 32, 8)])
        broadcast_address = '.'.join([str(int(broadcast_binary[i:i+8], 2)) for i in range(0, 32, 8)])

        if self.cidr == 31 or self.cidr == 32:
            first_host = "N/A"
            last_host = "N/A"
        else:
            first_host_binary = list(network_binary)
            first_host_binary[-1] = '1'
            first_host = '.'.join([str(int("".join(first_host_binary[i:i+8]), 2)) for i in range(0, 32, 8)])

            last_host_binary = list(broadcast_binary)
            last_host_binary[-1] = '0'
            last_host = '.'.join([str(int("".join(last_host_binary[i:i+8]), 2)) for i in range(0, 32, 8)])

        return {
            "Địa chỉ mạng": network_address,
            "Địa chỉ quảng bá": broadcast_address,
            "Địa chỉ trạm": f"{first_host} - {last_host}",
            "Loại": self.get_address_type()
        }

    def get_address_type(self):
        binary_ip = ''.join([format(part, '08b') for part in self.ip_parts])
        cidr = self.cidr
        mask = '1' * cidr + '0' * (32 - cidr)
        network_binary = ''.join([binary_ip[i] if mask[i] == '1' else '0' for i in range(32)])
        broadcast_binary = ''.join([binary_ip[i] if mask[i] == '1' else '1' for i in range(32)])

        if binary_ip == network_binary:
            return "Địa chỉ mạng"
        elif binary_ip == broadcast_binary:
            return "Địa chỉ quảng bá"
        elif self.cidr < 31:
            return "Địa chỉ trạm"
        else:
            return "Unknown"


class IPv6Address(IPAddress):
    def __init__(self, ip_with_cidr):
        super().__init__(ip_with_cidr)
        try:
            self.ip_str, self.cidr_str = ip_with_cidr.split('/')
            self.cidr = int(self.cidr_str)
        except ValueError:
            raise ValueError("Định dạng IPv6 không hợp lệ. Đúng định dạng là xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/Prefix.")

        # Kiểm tra prefix (CIDR)
        if not (0 <= self.cidr <= 128):
            raise ValueError("Prefix CIDR của IPv6 phải nằm trong khoảng từ 0 đến 128.")

        # Kiểm tra định dạng IPv6
        ip_parts = self.parse_ipv6(self.ip_str)  # Gọi phương thức parse_ipv6
        if len(ip_parts) != 8:
            raise ValueError("IPv6 phải có đúng 8 block và mỗi block là một số thập lục phân hợp lệ.")
        if not all(part == '0' or (1 <= len(part) <= 4 and all(c in '0123456789abcdefABCDEF' for c in part)) for part in ip_parts):
            raise ValueError("IPv6 phải chứa các giá trị thập lục phân hợp lệ trong các block.")

    def parse_ipv6(self, ip_str):
        """
        Phương thức xử lý chuỗi IPv6 (bao gồm các trường hợp chứa "::").
        """
        # Xử lý trường hợp đặc biệt: `::` (toàn bộ là số 0)
        if ip_str == "::":
            return ['0'] * 8

        parts = ip_str.split('::')
        if len(parts) > 2:
            raise ValueError("Địa chỉ IPv6 chỉ được chứa tối đa một dấu `::`.")

        left = parts[0].split(':') if parts[0] else []
        right = parts[1].split(':') if len(parts) > 1 and parts[1] else []
        missing = 8 - (len(left) + len(right))
        middle = ['0'] * missing
        return left + middle + right


    def classify(self):
        ip_parts_str = self.parse_ipv6(self.ip_str)
        if len(ip_parts_str) != 8:
            return "Invalid IPv6 Address"

        try:
            ip_parts_int = [int(p, 16) for p in ip_parts_str]
        except ValueError:
            return "Invalid IPv6 Address"

        if all(p == 0 for p in ip_parts_int):
            return "Unspecified Address (Địa chỉ không xác định): Chủ yếu sử dụng làm địa chỉ nguồn khi thiết bị khởi động và chưa có địa chỉ IP cụ thể."
        elif all(p == 0 for p in ip_parts_int[:-1]) and ip_parts_int[-1] == 1:
            return "Loopback IP: Được sử dụng để kiểm tra nội bộ trên thiết bị và không bao giờ truyền qua mạng."
        elif ip_parts_int[0] == 0xff02 and all(p == 0 for p in ip_parts_int[1:-1]) and ip_parts_int[-1] == 1:
            return "Link-Local All-Nodes Multicast: Gửi dữ liệu đến tất cả các thiết bị trong mạng cục bộ."
        elif ip_parts_int[0] == 0xff02 and all(p == 0 for p in ip_parts_int[1:-1]) and ip_parts_int[-1] == 2:
            return "Link-Local All-Routers Multicast: Gửi dữ liệu đến tất cả các router trong mạng cục bộ."
        elif 0xfc00 <= ip_parts_int[0] <= 0xfdff:
            return "Unique Local Address (ULA): Địa chỉ IP cục bộ duy nhất, tương tự địa chỉ riêng trong IPv4, không truy cập được từ Internet."
        elif 0xfe80 <= ip_parts_int[0] <= 0xfebf:
            return "Link-Local Address: Được sử dụng trong mạng cục bộ để giao tiếp giữa các thiết bị trên cùng một liên kết, tự động cấp phát."
        elif 0xff00 <= ip_parts_int[0] <= 0xffff:
            return "Multicast: Được sử dụng để gửi dữ liệu đến một nhóm thiết bị cụ thể trong mạng."
        elif ip_parts_int[0] == 0x2001 and ip_parts_int[1] == 0x0000:
            return "Teredo Address: Địa chỉ đặc biệt hỗ trợ giao tiếp giữa IPv4 và IPv6."
        elif self.ip_str.startswith("::ffff:"):  # IPv4-Mapped Address
            return "IPv4-Mapped Address: Địa chỉ IPv6 ánh xạ tới một địa chỉ IPv4, sử dụng để tương thích giữa IPv4 và IPv6."
        elif ip_parts_int[0] == 0x2001 and ip_parts_int[1] == 0x0002:  # Benchmarking Address
            return "Benchmarking Address: Được sử dụng để kiểm tra và đánh giá hiệu năng mạng IPv6."
        elif ip_parts_int[0] == 0x2001 and ip_parts_int[1] == 0x0010:  # Orchid Address
            return "Orchid Address: Được sử dụng cho mục đích thử nghiệm."
        elif ip_parts_int[0] == 0x2002:  # 6to4 Address
            return "6to4 Address: Địa chỉ hỗ trợ chuyển đổi giữa IPv4 và IPv6."
        elif ip_parts_int[0] == 0x2001 and ip_parts_int[1] == 0x0db8:  # Documentation Address
            return "Documentation Address: Được sử dụng trong tài liệu kỹ thuật và ví dụ, không dùng trên mạng thực tế."
        elif 0x2000 <= ip_parts_int[0] <= 0x3fff:  # Global Unicast Address
            return "Global Unicast Address (Địa chỉ IPv6 toàn cầu): Địa chỉ có thể định tuyến trên Internet, tương tự địa chỉ công cộng của IPv4."
        else:
            return "Other IPv6 Address: Địa chỉ không thuộc các loại trên, có thể là một địa chỉ hợp lệ khác."


class IPClassifierApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IP Address Classifier")
        self.root.geometry("650x450")
        self.root.resizable(False, False)

        # Nhãn tiêu đề
        self.title_label = tk.Label(root, text="IP Address Classifier", font=("Arial", 16))
        self.title_label.pack(pady=10)

        # Nhập địa chỉ IP với CIDR
        self.ip_entry_label = tk.Label(root, text="Enter IP Address with Subnet Mask (e.g., 192.168.1.1/24 or 2001:db8::1/64):")
        self.ip_entry_label.pack(pady=5)
        self.ip_entry = tk.Entry(root, width=60, font=("Arial", 12))
        self.ip_entry.pack(pady=5)
        self.ip_entry.bind("<Return>", self.classify_ip)

        # Nút kiểm tra
        self.classify_button = tk.Button(root, text="Classify IP", command=self.classify_ip, font=("Arial", 12), bg="blue", fg="white")
        self.classify_button.pack(pady=10)

        # Frame để chứa hai phần kết quả
        self.result_frame = tk.Frame(root)
        self.result_frame.pack(pady=10)

        # Nhãn hiển thị kết quả bên trái
        self.left_result_label = tk.Label(self.result_frame, text="", font=("Arial", 12), fg="green", wraplength=300, justify="left")
        self.left_result_label.pack(side="left", padx=10, anchor="nw")

        # Nhãn hiển thị kết quả bên phải
        self.right_result_label = tk.Label(self.result_frame, text="", font=("Arial", 12), fg="blue", wraplength=300, justify="left")
        self.right_result_label.pack(side="right", padx=10, anchor="ne")

    def classify_ip(self, event=None):
        ip_with_cidr = self.ip_entry.get().strip()
        if not ip_with_cidr:
            messagebox.showerror("Error", "Vui lòng nhập địa chỉ IP với subnet mask.")
            return

        if '/' not in ip_with_cidr:
            messagebox.showerror("Error", "Định dạng không hợp lệ. Đúng định dạng là A.B.C.D/Prefix hoặc IPv6/Prefix.")
            return

        self.left_result_label.config(text="")
        self.right_result_label.config(text="")

        try:
            if ':' in ip_with_cidr:
                ip_obj = IPv6Address(ip_with_cidr)
                left_text = f"IPv6 Address Type: {ip_obj.classify()}"
                self.left_result_label.config(text=left_text)
            else:
                ip_obj = IPv4Address(ip_with_cidr)
                left_text = f"IPv4 Address Type: {ip_obj.classify()}"
                self.left_result_label.config(text=left_text)
                details = ip_obj.get_details()
                right_text = "\n".join([f"{key}: {value}" for key, value in details.items()])
                self.right_result_label.config(text=right_text)

        except ValueError as e:
            messagebox.showerror("Error", str(e))
            self.left_result_label.config(text="Invalid IP Address or Subnet Mask")
            self.right_result_label.config(text="")


if __name__ == "__main__":
    root = tk.Tk()
    app = IPClassifierApp(root)
    root.mainloop()