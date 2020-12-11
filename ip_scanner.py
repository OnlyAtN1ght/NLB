from os import popen
from platform import system
from constants import *

def network_discovery():
   net = NETWORK
   net1= net.split('.')
   net2 = ".".join(net1) + '.'

   oper = system()

   liste_ip = []

   if (oper == "Windows"):
      ping1 = "ping -n 1 "
      flag = "TTL"
   elif (oper == "Linux"):
      ping1 = "ping -c 1 "
      flag = "ttl"
   else :
      ping1 = "ping -c 1 "
      flag = "ttl"

   for ip in range(1, 255):
      addr = net2 + str(ip)
      comm = ping1 + addr
      response = popen(comm)
      print(addr, "test...")
      for line in response.readlines():
         if (line.find(flag) != -1):
            liste_ip.append(addr)

   return liste_ip

if __name__ == '__main__':
   print(network_discovery())