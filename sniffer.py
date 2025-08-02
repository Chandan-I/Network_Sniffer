import tkinter as tk
from tkinter import ttk, messagebox
import socket
import threading
from packet_utils import parse_packet

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Sniffer")
        self.root.geometry("1100x600")

        self.sniffing = False
        self.sock = None
        self.protocol_filter = tk.StringVar(value="All")

        # Title Label
        tk.Label(root, text="Network Packet Sniffer", font=("Helvetica", 20, "bold")).pack(pady=10)

        # Buttons
        button_frame = tk.Frame(root)
        button_frame.pack(pady=10)

        self.start_button = tk.Button(button_frame, text="Start Sniffing", command=self.start_sniffing,
                                      width=20, bg="green", fg="white", font=("Arial", 12, "bold"))
        self.start_button.grid(row=0, column=0, padx=10)

        self.stop_button = tk.Button(button_frame, text="Stop Sniffing", command=self.stop_sniffing,
                                     width=20, bg="red", fg="white", font=("Arial", 12, "bold"), state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=10)

        # Filter and Clear Frame
        control_frame = tk.Frame(root)
        control_frame.pack(fill=tk.X, padx=20, pady=5)

        # Protocol Dropdown
        tk.Label(control_frame, text="Protocol Filter:", font=("Arial", 12)).pack(side=tk.LEFT)
        self.protocol_menu = ttk.Combobox(control_frame, textvariable=self.protocol_filter, state="readonly",
                                          values=["All", "TCP", "UDP", "ICMP", "Other"], width=10)
        self.protocol_menu.pack(side=tk.LEFT, padx=10)

        # Clear Table Button
        clear_button = tk.Button(control_frame, text="Clear Table", command=self.clear_table,
                                 bg="#444", fg="white", font=("Arial", 10, "bold"))
        clear_button.pack(side=tk.RIGHT)

        # Packet Table
        table_frame = tk.Frame(root)
        table_frame.pack(pady=10, fill=tk.BOTH, expand=True)

        columns = ("Source IP", "Destination IP", "Src Port", "Dst Port", "Domain", "Protocol")
        self.packet_table = ttk.Treeview(table_frame, columns=columns, show='headings')
        for col in columns:
            self.packet_table.heading(col, text=col)
            self.packet_table.column(col, anchor=tk.CENTER, width=150)
        self.packet_table.pack(expand=True, fill=tk.BOTH)

        self.packet_table.bind("<Double-1>", self.show_packet_detail)

    def start_sniffing(self):
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED, bg="gray", text="Sniffing Started")
        self.stop_button.config(state=tk.NORMAL)
        self.sniff_thread = threading.Thread(target=self.sniff_packets)
        self.sniff_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.stop_button.config(state=tk.DISABLED)
        self.start_button.config(state=tk.NORMAL, bg="green", text="Start Sniffing")

    def clear_table(self):
        for item in self.packet_table.get_children():
            self.packet_table.delete(item)

    def sniff_packets(self):
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create socket:\n{e}")
            return

        while self.sniffing:
            try:
                packet, _ = self.sock.recvfrom(65565)
                parsed = parse_packet(packet)
                if parsed:
                    selected_protocol = self.protocol_filter.get().upper()
                    if selected_protocol == "ALL" or parsed['protocol'].upper() == selected_protocol:
                        self.packet_table.insert('', 'end', values=(
                            parsed['src_ip'], parsed['dest_ip'],
                            parsed['src_port'], parsed['dest_port'],
                            parsed['domain'], parsed['protocol']
                        ))
            except Exception:
                pass

        if self.sock:
            self.sock.close()

    def show_packet_detail(self, event):
        selected = self.packet_table.focus()
        values = self.packet_table.item(selected, "values")
        if values:
            msg = "\n".join(f"{label}: {value}" for label, value in zip(
                ("Source IP", "Destination IP", "Source Port", "Destination Port", "Domain", "Protocol"), values))
            messagebox.showinfo("Packet Details", msg)

# Run GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()