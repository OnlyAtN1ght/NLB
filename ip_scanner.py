import  os
import platform 
from constants import *

def network_discovery():
   # String avec l'IP du serveur sans la partie hote
   network_without_machine = NETWORK[:-1] 

   # Os de la machine qui lance le code
   os = platform.system()

   liste_ip = []

   ping_command = "ping -n 1 " if os == "Windows" else "ping -c 1 "
   flag = "TTL" if os == "Windows" else "ttl"


   for ip_hote in range(1, 255):
      # Generation de la commande ping
      address_ip = network_without_machine + str(ip_hote)
      command = ping_command + address_ip

      # Execution de la reponse
      response = os.popen(command)
      print(address_ip, "test...")

      # On verifie le resulat de la commande
      for line in response.readlines():
         # On a une reponse 
         if (line.find(flag) != -1):
            liste_ip.append(address_ip)

   return liste_ip

if __name__ == '__main__':
   print(network_discovery())