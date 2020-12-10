from scapy.all import *
import random

#test
IP_serveur = "10.147.17.190"
COMPTEUR = 100
FLAG = 0
TIMEOUT = 200
LISTE_IP =[
		"10.147.17.190", #Lilian
        "10.147.17.75",  #Thomas
        "10.147.17.114", #Simon
        "10.147.17.69",  #Camille
        "10.147.17.32",  #Alan
        "10.147.17.154"] #Elouan
        
PORT = 50268

# INTERFACE DE ZTB
INTERFACE_NAME = "ztbpan3637"                          #(Pour Unix)
#INTERFACE_NAME = "ZeroTier One [8850338390ee78ef]"    #(Pour Windows)

global score

class GamePacket(Packet):
    name = "GamePacket"
    fields_desc=[IntField("compteur",0), IntField("flag", "0")]

def IP_propre():
	# Renvoie l'IP
	#return get_if_addr(IFACES.dev_from_name(INTERFACE_NAME))         #(Pour Windows)
	return get_if_addr(INTERFACE_NAME)                                #(Pour Unix)

def generation_paquet(compteur = COMPTEUR, flag = FLAG):
	# Fonction qui genere le premier paquet du jeu
	return GamePacket(compteur = compteur, flag = FLAG)

def trouve_destinataire():
	# Renvoie l'IP d'un des destinataires differents de celle de l'emeteur
	choix = random.choice(LISTE_IP)
	mon_ip = IP_propre()
	while choix == mon_ip:
		choix = random.choice(LISTE_IP)
	return choix

def envoie(paquet):
	destinataire = trouve_destinataire()
	print(destinataire)

	# On construit le paquet
	paquet_construit = IP(dst=destinataire)/UDP(dport = PORT,sport = 15)/paquet
	paquet_construit.show()
	
	# Envoie du paquet
	send(paquet_construit)

def callback_paquet_recu(paquet):
	paquet_class = GamePacket(paquet[Raw].load)
	paquet_class.show()
        
	score = score + 1
	print("Mon score est ", score)
	# On cherche la valeur actuelle du counter contenue dans le paquet
	src = paquet[IP].src
	dst = paquet[IP].dst
	valeur = getattr(paquet_class["GamePacket"], "compteur")
	flag = getattr(paquet_class["GamePacket"], "flag")
	print(valeur)
	print("Source :",src)
	print("Destination :",dst)

	if (dst == IP_propre() and dst!="10.147.17.255") or flag != 0:
            if valeur > 0 and flag == 0:
            	print("Paquet recu de compteur > 0")
            	nouveau_paquet = generation_paquet(int(valeur)-1, 0)
            	envoie(nouveau_paquet)
            	print("Envoie paquet avec compteur - 1")
            elif valeur == 0 and flag == 0:
            	print("Paquet de fin recu")
            	end_paquet = GamePacket(compteur = 0, flag = 1)
            	send(IP(dst=IP_serveur)/UDP(dport = PORT,sport = 15)/end_paquet)
            	print("Paquet d'annonce de fin au serveur envoyer")
            elif flag == 2:
            	print("Paquet de demande de score recu")
            	score_paquet = GamePacket(compteur = score, flag = 3)
            	send(IP(dst=IP_serveur)/UDP(dport = PORT,sport = 15)/score_paquet)
            	print("Paquet d'annonce de score envoyé")
            elif flag == 4:
            	print("Paquet d'annonce de vainqueur recu")
            	pass

def attente_paquet():
	# On attend
	print("En attente d'un paquet : ")
	sniff(filter = "port {PORT}".format(PORT = PORT),iface = INTERFACE_NAME, prn = callback_paquet_recu)

def main():
	score = 0
	attente_paquet()

if __name__ == '__main__':
	main()