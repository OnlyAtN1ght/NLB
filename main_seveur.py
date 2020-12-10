from scapy.all import *
import random
from sys import exit

#test
IP_serveur = "10.147.17.190"
COMPTEUR = 100
TIMEOUT = 200
FLAG = 0
LISTE_IP =[
		"10.147.17.190", #Lilian
		"10.147.17.75",  #Thomas
		"10.147.17.114", #Simon
		#"10.147.17.69",  #Camille
		"10.147.17.32",  #Alan
		"10.147.17.154"  #Elouan
		] 
PORT = 50268

# INTERFACE DE ZTB
INTERFACE_NAME = "ztbpan3637"                          #(Pour Unix)
#INTERFACE_NAME = "ZeroTier One [8850338390ee78ef]"    #(Pour Windows)

score_final = {}
score = 0

class GamePacket(Packet):
	name = "GamePacket"
	fields_desc=[IntField("compteur",0), IntField("flag", "0")]

def generation_paquet(compteur = COMPTEUR, flag = FLAG):
	# Fonction qui genere le premier paquet du jeu
	return GamePacket(compteur = compteur, flag = FLAG)

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

	# On construit le paquet
	paquet_construit = IP(dst=destinataire)/UDP(dport = PORT,sport = 15)/paquet
	
	# Envoie du paquet
	send(paquet_construit)

def calcul_vainqueur():
	global score_final
	print(score_final)
	score_final_table = sorted(score_final, key = score_final.get, reverse = True)
	print("Le vainqueur est : ", score_final_table[0])
	exit()

def recup_score(paquet = 0):
	global score_final
	global score
	if paquet != 0:
		paquet_class = GamePacket(paquet[Raw].load)
		score_final[paquet[IP].src] = getattr(paquet_class["GamePacket"], "compteur")
	score_final[IP_serveur] = score
	if len(score_final) != len(LISTE_IP):
		sniff(filter = "port {PORT}".format(PORT = PORT), iface = INTERFACE_NAME, prn = recup_score)
	calcul_vainqueur()

def ask_score():
	ask = GamePacket(compteur = 0, flag = 2)
	ask_build = IP(dst="10.147.17.255")/UDP(dport = PORT,sport = 15)/ask
	send(ask_build)
	print("Envoie flag 2")
	recup_score()

def callback_paquet_recu(paquet):
	print("\n\n\n")
	global score
	paquet_class = GamePacket(paquet[Raw].load)

	# On cherche la valeur actuelle du counter contenue dans le paquet
	src = paquet[IP].src
	dst = paquet[IP].dst
	valeur = getattr(paquet_class["GamePacket"], "compteur")
	flag = getattr(paquet_class["GamePacket"], "flag")
	print("Compteur reçu :",valeur)
	print("Flag reçu :", flag)
	print("Source :",src)
	print("Destination :",dst)

	if dst == IP_propre() and dst!="10.147.17.255" and flag == 0 and valeur > 0:
		nouveau_paquet = generation_paquet(int(valeur)-1)
		envoie(nouveau_paquet)
		score = score + 1
		print("Mon score est", score)
		print("Envoie")
	
	elif dst == IP_propre() and dst!="10.147.17.255" and ((flag == 0 and valeur == 0) or flag == 1):
		ask_score()

def attente_paquet():
	# On attend
	# INTERFACE_NAME = "ZeroTier One [8850338390ee78ef]"
	print("En attente d'un paquet : ")
	sniff(filter = "port {PORT}".format(PORT = PORT), iface = INTERFACE_NAME, prn = callback_paquet_recu)

def main():
	if True:#IP_propre() == IP_serveur:
		paquet_debut = generation_paquet()
		envoie(paquet_debut)
	attente_paquet()


if __name__ == '__main__':
	main()