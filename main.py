from scapy.all import *
import random

#test
IP_serveur = "0.0.0.0"
COMPTEUR = 100
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
INTERFACE_NAME = "ztbpan3637"
#INTERFACE_NAME = conf.iface
#INTERFACE_NAME = "ZeroTier One [8850338390ee78ef]"

global score

class GamePacket(Packet):
    name = "GamePacket"
    fields_desc=[ IntField("compteur",0)]

def generation_paquet(compteur = COMPTEUR):
	# Fonction qui genere le premier paquet du jeu
	return GamePacket(compteur = compteur)

def IP_propre():
	# Renvoie l'IP
	#return get_if_addr(IFACES.dev_from_name(INTERFACE_NAME)) (LAISSE CA STP) 
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
	#destinataire = "10.147.17.190"
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

	# On cherche la valeur actuelle du counter contenue dans le paquet
	src = paquet[IP].src
	dst = paquet[IP].dst
	valeur = getattr(paquet_class["GamePacket"], "compteur")
	print(valeur)
	print("Source :",src)
	print("Destination :",dst)

	if dst ==IP_propre() and dst!="10.147.17.255":
            if valeur > 0 :
                nouveau_paquet = generation_paquet(int(valeur)-1)
                envoie(nouveau_paquet)
                print("Envoie")
            elif valeur==0:
                print("FLAN")
	# On crée le nouveau paquet 
	#nouveau_paquet = generation_paquet(int(valeur)-1)

	# On renvoie le nouveau paquet 
	#envoie(nouveau_paquet)



def attente_paquet():
	# On attend
	# INTERFACE_NAME = "ZeroTier One [8850338390ee78ef]"
	print("En attente d'un paquet : ")
	sniff(filter = "port {PORT}".format(PORT = PORT),iface = INTERFACE_NAME, prn = callback_paquet_recu)

def main():
  score = 0
  if True:#IP_propre() == IP_serveur:
    paquet_debut = generation_paquet()
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
