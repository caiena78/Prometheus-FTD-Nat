

import ipaddress
import socket
from netmiko import ConnectHandler
import re





class firewall:
    user=""
    password=""
    def __init__(self,user,password) -> None:
        self.user=user
        self.password=password
 
    def getDevice(self,ip):    
        device={
            'device_type': 'cisco_ftd_ssh',
            'host':   ip,
            'username': self.user,
            'password': self.password,
            'port' : 22,          
            'conn_timeout' : 40,
            'global_delay_factor': 30,
            'secret':"",          
        }      
        return device

    def is_valid_ipv4(self,address):
        try:
            # Try to create an IPv4 address object
            ip = ipaddress.IPv4Address(address)
            return True
        except ipaddress.AddressValueError:
            return False

    def sendCMD(self, device,command,textfsm=False):
        
        with  ConnectHandler(**device) as net_connect:                
            if net_connect.check_enable_mode() == False:
                net_connect.enable()
            Data = net_connect.send_command(command,use_textfsm=textfsm)        
        return Data

    def is_port_open(self, host,port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)  # Set a timeout for the connection attempt
        try:
            s.connect((host, port))
            s.close()
            return True
        except (socket.timeout, socket.error):
            return False
    
    def dataparser(self,data):
        nat_data=[]
        pattern=r'(TCP|UDP|ICMP) PAT pool (\S+), address (\b(?:\d{1,3}\.){3}\d{1,3}\b), range (\d{1,5})-(\d{1,5}), allocated (\d{1,8})'
        data=re.findall(pattern,data)
        if not data:
            return []
        for item in data:
            nat_data.append({
                "protocol":item[0],
                "interface":item[1],
                "ip":item[2],
                "range_start":int(item[3]),
                "range_end":int(item[4]),
                "size":item[5]
            })
        return nat_data

    def getNatPool(self,ipaddress):
        cmd="show nat pool"
        if self.is_valid_ipv4(ipaddress):
            device=self.getDevice(ipaddress)
        else:
            raise Exception("IP ADDRESS is not valid")        
        if not self.is_port_open(ipaddress,22):
            raise Exception(f"Unable to connect to {ipaddress} on tcp/22")               
        data=self.sendCMD(device,cmd)
        nat_data=self.dataparser(data)
        return nat_data
    




