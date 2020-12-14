from scapy.all import *
import random
from sys import exit
from time import sleep
import platform 

from constants import *
from ip_scanner import *

SCORE_PERSO = 0
#LISTE_IP = network_discovery()
OS = platform.system()

class GamePacket(Packet):
	name = "GamePacket"
	fields_desc=[IntField("compteur",0), IntField("flag", "0")]

def IP_propre():
	# Renvoie l'IP de la machine qui lance le porgramme 
	if OS == "Windows":
		return get_if_addr(IFACES.dev_from_name(INTERFACE_NAME))
	return get_if_addr(INTERFACE_NAME)

def trouve_destinataire_aleatoire():
	# Renvoie l'IP d'un des destinataires differents de celle de l'emeteur
	choix = random.choice(LISTE_IP)
	mon_ip = IP_propre()

	# Tant que l'ip choisit est la meme que celle de la machine on en chosit une autre
	while choix == mon_ip:
		choix = random.choice(LISTE_IP)
	return choix

def envoie(paquet, destinataire = None):
	# Envoie le paquet à un destinataire chosit aléatoirement
	if not destinataire:
		destinataire = trouve_destinataire_aleatoire()

	# On construit le paquet
	paquet_construit = IP(dst=destinataire)/UDP(dport = PORT,sport = 15)/paquet
	
	# Envoie du paquet
	send(paquet_construit)

def callback_paquet_recu(paquet):
	global SCORE_PERSO
	paquet_class = GamePacket(paquet[Raw].load)

	# On récupre toutes les informations contenues dans le paquet
	src = paquet[IP].src
	dst = paquet[IP].dst
	valeur = getattr(paquet_class["GamePacket"], "compteur")
	flag = getattr(paquet_class["GamePacket"], "flag")

	# On verifie que le message nous est adressé ( et que le message n'est pas en broadcast)
	# On verfie que le flag du paquet est 2 ou 4, c'est à dire que le paquet provient du serveur 
	if (dst == IP_propre() and dst != "10.147.17.255") or flag == 2 or flag == 4:
		
		# Affichage des données du paquet recu 
		print("\n\n")
		print("Compteur reçu :",valeur)
		print("Flag reçu :", flag)
		print("Source :",src)
		print("Destination :",dst)
		
		# Cas normal du jeu 
		if valeur > 0 and flag == 0:
			nouveau_paquet = GamePacket(compteur = int(valeur)-1, flag = 0)
			SCORE_PERSO = SCORE_PERSO + 1
			print("Mon score est", SCORE_PERSO)
			envoie(nouveau_paquet)

		# Cas où l'on est le dernier joueur du jeu
		elif valeur == 0 and flag == 0:
			# On indique au serveur que le jeu est fini 
			end_paquet = GamePacket(compteur = 0, flag = 1)
			envoie(end_paquet,IP_SERVEUR)

		# Cas où le serveur demande les scores 
		elif flag == 2:
			# Pour que tout le monde n'envoye pas ses messages en meme temps, chaque joueur sleep une durée differente
			# La durée depend de l'adresse IP propre
			sleep(LISTE_IP.index(IP_propre()) + 1)

			# On genere le paquet qui contient le score 
			score_paquet = GamePacket(compteur = SCORE_PERSO, flag = 3)
			# On l'envoie 
			envoie(score_paquet,IP_SERVEUR)

		# Cas où le serveur envoie le vainqueur 
		elif flag == 4:
			if valeur == -1:
				print("Une erreur est survenue, un tricheur parmi nous ?")
				exit()
			print("\nLe vainqueur est", LISTE_IP[valeur])
			exit()

def attente_paquet():
	# On attend
	print("En attente d'un paquet : ")
	sniff(filter = "port {PORT}".format(PORT = PORT),iface = INTERFACE_NAME, prn = callback_paquet_recu)

def main():
	attente_paquet()

if __name__ == '__main__':
	main()