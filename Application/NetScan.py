import socket
import platform
import psutil
import ping3
import threading


class NetScan:
  def __init__(self):
    self.os_type = platform.system()  
    self.net_interfaces = []
    for interface, addresses in psutil.net_if_addrs().items():
      dictionary_to_push = {
        'name': interface,
        'adresses': {
          'ipv4': '',
          'ipv6': '',
        },
        'netmask': ''
      }
      for address in addresses:
        if (address.family == 2):
          dictionary_to_push['adresses']['ipv4'] = address.address
          dictionary_to_push['netmask'] = address.netmask
        elif (address.family == 23):
          dictionary_to_push['adresses']['ipv6'] = address.address
      self.net_interfaces.append(dictionary_to_push)
    self.network_mask = self.net_interfaces[0]['netmask']

  def GetInterfaces(self):
    return self.net_interfaces

  def MyIP(self):
    return socket.gethostbyname(socket.getfqdn())
    
  def GetMyHostName(self):
    return socket.gethostname()
  
  def ShowAvaibleIps(self):
    ethernet = self.net_interfaces[0]
    ipv4 = ethernet['adresses']['ipv4']
    octets_ip, octets_nm = ipv4.split('.'), self.network_mask.split('.')
    for i in range(4):
      octets_ip[i] = int(octets_ip[i]) & int(octets_nm[i])
    
    number_of_adresses = 0
    for i in range(4):
      diff = 255 - int(octets_nm[i])
      number_of_adresses += diff    
    avaible_devices = []
    threads = []
    # now we need to create a socket for each ip avaible and check if it is in use
    for i in range(number_of_adresses):
      octets_ip[3] += 1
      if (octets_ip[3] > 255):
        octets_ip[3] = 0
        octets_ip[2] += 1
        if (octets_ip[2] > 255):
          octets_ip[2] = 0
          octets_ip[1] += 1
          if (octets_ip[1] > 255):
            octets_ip[1] = 0
            octets_ip[0] += 1
      ip = '.'.join([str(octect) for octect in octets_ip])
      thread = threading.Thread(target=self.ConnectionWith, args=(ip, avaible_devices))
      threads.append(thread)
      thread.start()
    for thread in threads:
      thread.join()
    return avaible_devices
  
  def ConnectionWith(self, ip, container = None):
    condition = ping3.ping(ip, timeout=0.5) != None
    if (condition and container != None):
      container.append(ip)
    return condition
  
  def GetOpenedPorts(self, ip, range_p = 65535):
    ports = []
    threads = []
    for port in range(range_p + 1):
      # Maybe not necesary, but if an exception is raised, the socket will be closed automatically
      thread = threading.Thread(target=self.IsPortOpen, args=(ip, port, ports))
      threads.append(thread)
      thread.start()
    for thread in threads:
      thread.join()
    return ports
  
  def IsPortOpen(self, ip, port, container = None):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: 
      result = s.connect_ex((ip, port))
      if (result == 0 and container != None):
        container.append(port)
        s.close()
      return result == 0