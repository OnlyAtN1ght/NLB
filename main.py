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
PORT = 50268

# INTERFACE DE ZTB
INTERFACE_NAME = "ztbpan3637b"


class GamePacket(Packet):
    name = "GamePacket"
    fields_desc=[ IntField("compteur",0)]

def generation_paquet_depart():
	# Fonction qui genere le premier paquet du jeu
	return GamePacket(compteur = COMPTEUR)

def IP_propre():
	# Renvoie l'IP 
	return get_if_addr(INTERFACE_NAME)

def trouve_destinataire():
	# Renvoie l'IP d'un des destinataires differents de celle de l'emeteur
	choix = random.choice(LISTE_IP)
	mon_ip = IP_propre()
	while choix == mon_ip:
		choix = random.choice(LISTE_IP)
	return choix

def envoie(paquet):
	destinataire = trouve_destinataire()
	destinataire = "10.147.17.5"
	print(destinataire)

	# On construit le paquet
	paquet_construit = IP(dst=destinataire)/UDP(dport = PORT,sport = 15)/GamePacket(compteur = COMPTEUR)
	paquet_construit.show()
	# Envoie du paquet
	send(paquet_construit)

def callback_paquet_recu(paquet):
	paquet_class = GamePacket(paquet[Raw].load)
	paquet_class.show()

def attente_paquet():
	# On attend
	print("En attente d'un paquet : ")
	sniff(filter = "port {PORT}".format(PORT = PORT),iface = "ztbpan3637", prn = callback_paquet_recu)

def main():
	# Main
	if True:#IP_propre() == IP_serveur:
		paquet_debut = generation_paquet_depart()
		envoie(paquet_debut)

	attente_paquet()




if __name__ == '__main__':
	main()


# TODO : interfaces reseaux

"""
Champs :
nom du paquet : “GamePacket”
ttl ? (à choisir : propose 30)
src : adresse IP source (pas besoin sur scapy)
dst : adresse IP destination (pas besoin)





"""
