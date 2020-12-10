from scapy.all import *
import random
from sys import exit

from constants import *

score_final = {}
SCORE_PERSO = 0

class GamePacket(Packet):
	name = "GamePacket"
	fields_desc=[IntField("compteur",0), IntField("flag", "0")]

def generation_paquet(compteur = COMPTEUR, flag = FLAG):
	# Fonction qui genere le premier paquet du jeu
	return GamePacket(compteur = compteur, flag = FLAG)

def IP_propre():
	# Renvoie l'IP de la machine qui lance le porgramme 
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

def calcul_vainqueur():
	global score_final

	print(score_final)

	# On trie le dictionnaire des scores
	score_final_table = sorted(score_final, key = score_final.get, reverse = True)
	# score_final_table : listes des adresses IP des joueurs triées en fonction de leurs scores

	print("Le vainqueur est : ", score_final_table[0])

	# On envoie le vainqueur à tous les joueurs
	adrresse_IP_vainqueur = LISTE_IP.index(score_final_table[0])
	vainqueur_paquet = GamePacket(compteur = adrresse_IP_vainqueur, flag = 4)
	envoie(vainqueur_paquet,"10.147.17.255")
	exit()

def recup_score(paquet = 0):
	global score_final
	global SCORE_PERSO

	# Dans le cas où l'on a recu un paquet avec un score
	if paquet != 0:
		# On récupere le score
		paquet_class = GamePacket(paquet[Raw].load)
		score_recu = getattr(paquet_class["GamePacket"], "compteur")

		# On l'ajoute au dictionnaire des scores 
		score_final[paquet[IP].src] = score_recu

	# On rajoute le score du serveur
	score_final[IP_SERVEUR] = SCORE_PERSO

	# Dans le cas où l'on a pas tous les scores 
	if len(score_final) != len(LISTE_IP):
		# Demande des scores
		sniff(filter = "port {PORT}".format(PORT = PORT), iface = INTERFACE_NAME, prn = recup_score)
	
	# On passe à l'étape du calcul du vainqueur  
	calcul_vainqueur()

def ask_score():
	# Fonction qui crée le paquet de demande de score et qui l'envoie 
	paquet_ask = GamePacket(compteur = 0, flag = 2)
	envoie(paquet_ask"10.147.17.255",)

	# On passe a l'étape de récuperation des scores
	recup_score()

def callback_paquet_recu(paquet):
	print("\n\n")

	global SCORE_PERSO

	paquet_class = GamePacket(paquet[Raw].load)


	# On récupre toutes les informations contenues dans le paquet
	src = paquet[IP].src
	dst = paquet[IP].dst
	valeur = getattr(paquet_class["GamePacket"], "compteur")
	flag = getattr(paquet_class["GamePacket"], "flag")

	# Affichage des données du paquet recu 
	print("Compteur reçu :",valeur)
	print("Flag reçu :", flag)
	print("Source :",src)
	print("Destination :",dst)


	# On verifie que le paquet nous est destiné et que le jeu est en fonctionement et n'est pas fini
	if dst == IP_propre() and dst!="10.147.17.255" and flag == 0 and valeur > 0:
		# On genere le nouveau paquet de jeu
		nouveau_paquet = GamePacket(compteur = int(valeur)-1, flag = 0)
		envoie(nouveau_paquet)

		SCORE_PERSO = SCORE_PERSO + 1
		print("Mon score est", SCORE_PERSO)
	
	# Le jeu vient de se finir et on passe a l'étape de demande de score 
	elif dst == IP_propre() and dst!="10.147.17.255" and ((flag == 0 and valeur == 0) or flag == 1):
		ask_score()

def attente_paquet():
	# On attend
	print("En attente d'un paquet : ")
	sniff(filter = "port {PORT}".format(PORT = PORT), iface = INTERFACE_NAME, prn = callback_paquet_recu)

def main():
	# On genere le premier paquet du jeu et on l'envoie 
	paquet_debut = generation_paquet()
	envoie(paquet_debut)
	attente_paquet()


if __name__ == '__main__':
	main()