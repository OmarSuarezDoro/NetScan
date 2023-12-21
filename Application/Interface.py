from tkinter import *

class Interface(Frame):
  def __init__(self, master=None):
    super().__init__(master)
    self.master = master
    self.master.title("NetScanner")
    self.pack(padx=10, pady=10)
    self.create_widgets()

  def create_widgets(self):
    # Frame para los controles de red
    frame_network = Frame(self)
    frame_network.pack(pady=10)

    # Labels
    Label(frame_network, text="Network Interfaces:").grid(row=0, column=0, sticky="w", pady=5)

    # ScrolledText para mostrar interfaces de red (más ancho y con fondo claro)
    self.text_interfaces = scrolledtext.ScrolledText(frame_network, height=8, width=60, bg="lightgray", wrap=WORD)
    self.text_interfaces.grid(row=1, column=0, padx=10, columnspan=2)

    # Botón para obtener interfaces de red
    ttk.Button(frame_network, text="Get Interfaces", command=self.get_interfaces).grid(row=2, column=0, columnspan=2, pady=5, sticky="ew")

    # Frame para las direcciones IP
    frame_ips = Frame(self)
    frame_ips.pack(pady=10)

    # Labels
    Label(frame_ips, text="Available IPs:").grid(row=0, column=0, sticky="w", pady=5)

    # ScrolledText para mostrar IPs disponibles (más ancho)
    self.text_available_ips = scrolledtext.ScrolledText(frame_ips, height=8, width=60, wrap=WORD, bg="lightgray")
    self.text_available_ips.grid(row=1, column=0, padx=10, columnspan=2)

    # Botón para mostrar IPs disponibles
    ttk.Button(frame_ips, text="Show Available IPs", command=self.show_available_ips).grid(row=2, column=0, columnspan=2, pady=5, sticky="ew")

    # Frame para puertos
    frame_ports = Frame(self)
    frame_ports.pack(pady=10)

    # Labels y Entradas
    Label(frame_ports, text="Enter IP:").grid(row=0, column=0, sticky="w", pady=5)
    self.entry_ip = Entry(frame_ports)
    self.entry_ip.grid(row=0, column=1, padx=10)

    Label(frame_ports, text="Enter Port Range (e.g., 1000, 2000..):").grid(row=1, column=0, sticky="w", pady=5)
    self.entry_ports = Entry(frame_ports)
    self.entry_ports.grid(row=1, column=1, padx=10)

    # ScrolledText para mostrar puertos abiertos (con fondo claro, desactivado para escribir)
    self.text_opened_ports = scrolledtext.ScrolledText(frame_ports, height=8, width=60, bg="lightgray", wrap=WORD, state=DISABLED)
    self.text_opened_ports.grid(row=3, column=0, columnspan=2, pady=10)

    # Botón para obtener puertos abiertos
    ttk.Button(frame_ports, text="Get Opened Ports", command=self.get_opened_ports).grid(row=2, column=0, columnspan=2, pady=5, sticky="ew")

    # Botón para salir de la aplicación
    ttk.Button(self, text="QUIT", command=self.master.destroy).pack(side="bottom", pady=10, fill="both", expand=True)

  # Resto del código (funciones get_interfaces, show_available_ips, get_opened_ports)

  # Function to get network interfaces
  def get_interfaces(self):
    self.text_interfaces.delete(1.0, END)  # Clear previous entries
    scanner = NetScan()
    interfaces = scanner.GetInterfaces()
    for interface in interfaces:
      self.text_interfaces.insert(END, f"{interface['name']} - IPv4: {interface['adresses']['ipv4']}\n")

  # Function to show available IPs
  def show_available_ips(self):
    self.text_available_ips.delete(1.0, END)  # Clear previous entries
    scanner = NetScan()
    available_ips = scanner.ShowAvaibleIps()
    for ip in available_ips:
      self.text_available_ips.insert(END, f"{ip}\n")

  # Function to get opened ports for a specific IP and port range
  def get_opened_ports(self):
    ip = self.entry_ip.get()
    port_range = self.entry_ports.get()

    if not ip or not port_range:
      messagebox.showwarning("Missing Information", "Please enter both IP and Port Range.")
      return

    scanner = NetScan()
    opened_ports = scanner.GetOpenedPorts(ip, int(port_range))

    # Limpiar el ScrolledText antes de agregar los nuevos puertos
    self.text_opened_ports.config(state=NORMAL)
    self.text_opened_ports.delete(1.0, END)

    # Agregar los puertos abiertos al ScrolledText
    self.text_opened_ports.insert(END, f"Opened ports for {ip} in range {port_range}:\n")
from tkinter import ttk, scrolledtext, messagebox
from Application.NetScan import NetScan

class Interface(Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.master.title("NetScanner")
        self.pack(padx=10, pady=10)
        self.create_widgets()

    def create_widgets(self):
        # Frame para los controles de red
        frame_network = Frame(self)
        frame_network.pack(pady=10)

        # Labels
        Label(frame_network, text="Network Interfaces:").grid(row=0, column=0, sticky="w", pady=5)

        # ScrolledText para mostrar interfaces de red (más ancho y con fondo claro)
        self.text_interfaces = scrolledtext.ScrolledText(frame_network, height=8, width=60, bg="lightgray", wrap=WORD)
        self.text_interfaces.grid(row=1, column=0, padx=10, columnspan=2)

        # Botón para obtener interfaces de red
        ttk.Button(frame_network, text="Get Interfaces", command=self.get_interfaces).grid(row=2, column=0, columnspan=2, pady=5, sticky="ew")

        # Frame para las direcciones IP
        frame_ips = Frame(self)
        frame_ips.pack(pady=10)

        # Labels
        Label(frame_ips, text="Available IPs:").grid(row=0, column=0, sticky="w", pady=5)

        # ScrolledText para mostrar IPs disponibles (más ancho)
        self.text_available_ips = scrolledtext.ScrolledText(frame_ips, height=8, width=60, wrap=WORD, bg="lightgray")
        self.text_available_ips.grid(row=1, column=0, padx=10, columnspan=2)

        # Botón para mostrar IPs disponibles
        ttk.Button(frame_ips, text="Show Available IPs", command=self.show_available_ips).grid(row=2, column=0, columnspan=2, pady=5, sticky="ew")

        # Frame para puertos
        frame_ports = Frame(self)
        frame_ports.pack(pady=10)

        # Labels y Entradas
        Label(frame_ports, text="Enter IP:").grid(row=0, column=0, sticky="w", pady=5)
        self.entry_ip = Entry(frame_ports)
        self.entry_ip.grid(row=0, column=1, padx=10)

        Label(frame_ports, text="Enter Port Range (e.g., 1000, 2000..):").grid(row=1, column=0, sticky="w", pady=5)
        self.entry_ports = Entry(frame_ports)
        self.entry_ports.grid(row=1, column=1, padx=10)

        # ScrolledText para mostrar puertos abiertos (con fondo claro, desactivado para escribir)
        self.text_opened_ports = scrolledtext.ScrolledText(frame_ports, height=8, width=60, bg="lightgray", wrap=WORD, state=DISABLED)
        self.text_opened_ports.grid(row=3, column=0, columnspan=2, pady=10)

        # Botón para obtener puertos abiertos
        ttk.Button(frame_ports, text="Get Opened Ports", command=self.get_opened_ports).grid(row=2, column=0, columnspan=2, pady=5, sticky="ew")

        # Botón para salir de la aplicación
        ttk.Button(self, text="QUIT", command=self.master.destroy).pack(side="bottom", pady=10, fill="both", expand=True)

    # Resto del código (funciones get_interfaces, show_available_ips, get_opened_ports)

    # Function to get network interfaces
    def get_interfaces(self):
        self.text_interfaces.delete(1.0, END)  # Clear previous entries
        scanner = NetScan()
        interfaces = scanner.GetInterfaces()
        for interface in interfaces:
            self.text_interfaces.insert(END, f"{interface['name']} - IPv4: {interface['adresses']['ipv4']}\n")

    # Function to show available IPs
    def show_available_ips(self):
        self.text_available_ips.delete(1.0, END)  # Clear previous entries
        scanner = NetScan()
        available_ips = scanner.ShowAvaibleIps()
        for ip in available_ips:
            self.text_available_ips.insert(END, f"{ip}\n")

    # Function to get opened ports for a specific IP and port range
    def get_opened_ports(self):
        ip = self.entry_ip.get()
        port_range = self.entry_ports.get()

        if not ip or not port_range:
            messagebox.showwarning("Missing Information", "Please enter both IP and Port Range.")
            return

        scanner = NetScan()
        opened_ports = scanner.GetOpenedPorts(ip, int(port_range))

        # Limpiar el ScrolledText antes de agregar los nuevos puertos
        self.text_opened_ports.config(state=NORMAL)
        self.text_opened_ports.delete(1.0, END)

        # Agregar los puertos abiertos al ScrolledText
        self.text_opened_ports.insert(END, f"Opened ports for {ip} in range {port_range}:\n")
        for port in opened_ports:
            self.text_opened_ports.insert(END, f"{port}\n")

        # Desactivar la posibilidad de escribir en el ScrolledText después de agregar los puertos
        self.text_opened_ports.config(state=DISABLED)
