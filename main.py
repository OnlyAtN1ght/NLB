from scapy.all import *
import random

IP_serveur = "0.0.0.0"
COMPTEUR = 100
TIMEOUT = 200
LISTE_IP =[
	"10.147.17.6",
	"10.147.17.12",
	"10.147.17.116",
	"10.147.17.79",
	"10.147.17.69",
	"10.147.17.7",
	"10.147.17.163",
	"10.147.17.209",
	"10.147.17.32",
	"10.147.17.204",
	"10.147.17.119",
	"10.147.17.130",
	"10.147.17.154",
	"10.147.17.183",
	"10.147.17.160",
	"10.147.17.67",
	"10.147.17.16",
	"10.147.17.155",
	"10.147.17.190",
	"10.147.17.75",
	"10.147.17.80"]

# INTERFACE DE ZTB
INTERFACE_NAME = "feth4232"
class GamePacket(Packet):
    name = "GamePacket"
    fields_desc=[ IntField("compteur",0)]

def generation_paquet_depart():
	# Fonction qui genere le premier paquet du jeu
	p = GamePacket(compteur = COMPTEUR)
	return p

def IP_propre():
	return get_if_addr(INTERFACE_NAME)

def trouve_destinataire():
	choix = random.choice(LISTE_IP)
	mon_ip = IP_propre()
	while choix == mon_ip:
		choix = random.choice(LISTE_IP)
	return choix

def envoie(paquet):
	destinataire = trouve_destinataire()
	destinataire = "10.147.17.190"
	print(destinataire)

	# 

	# envoie d'un paquet
	sr(IP(dst=destinataire)/TCP(sport=666,dport=(440,443),flags="S"))

	send(IP(dst=destinataire)/paquet, return_packets=True)




if __name__ == '__main__':
	# Main 
	paquet_debut = generation_paquet_depart()
	envoie(paquet_debut)

	#ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="10.147.17.0/24"),timeout=TIMEOUT)
	#ans.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%") )
	#ans, unans = sr(IP(dst="192.168.1.1-254")/ICMP())
"""
Champs :
nom du paquet : “GamePacket”
ttl ? (à choisir : propose 30)
src : adresse IP source (pas besoin sur scapy)
dst : adresse IP destination (pas besoin)





"""