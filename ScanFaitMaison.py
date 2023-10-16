#! /usr/bin/python

from scapy.all import *
import random

#==========FONCTIONS==============
def randomPorts(pMin, pMax, num_ranges):
	range_list = [(i, i + num_ranges - 1) for i in range(pMin, pMax + 1, num_ranges)]
	random.shuffle(range_list)
	return range_list

#===========SCAN TCP=============
def LeScan(pMin, pMax, num_ranges, LesFlags, TypeScan, ipCible):
	ListePorts = randomPorts(pMin, pMax, num_ranges)
	print ("\nScan en cours...")
	listPortsOuverts = []
	listPortsFermer = []

#--------------Envoi des packets----------------
	for i in ListePorts:
		trame = Ether()/IP(dst=ipCible)/TCP(sport=57915, dport=i, flags=LesFlags)
		reponse = srp(trame, timeout=1, verbose=False)

#-------------------------Récuperation des reponses----------------------------
		for y in range(len(reponse[0])):
			reponseFlags = (reponse[0][y][1].getlayer(TCP).flags)
			reponsePort = (reponse[0][y][1].getlayer(TCP).sport)
			if reponseFlags != "RA":
				listPortsOuverts.append((reponsePort, reponseFlags)
			if reponseFlags == "RA" or reponseFlags == "R":
				listPortsFermer.append((reponsePort))

#---------------------------Analise des reponses--------------------------------
	print ("\nLa liste des ports ouverts : ")
	for r1 in listPortsOuverts:
		print ("port =",r1[0]," ---------->reponse =",r1[1])
	if listPortsFermer == []:
		print ("Machine non vunerable au scan")
	else:
		print ("\nLa liste des ports potentiellement ouverts : ")
		for r2 in range(pMin, pMax):
			if r2 not in listPortsFermer:
				print ("port = ",r2)

#=============SCAN UDP=======================

#Pas encore developper

#=#=#=#=#=#=#=#=#=#=LANCEMENT DU SCAN=#=#=#=#=#=#=#=#=#=#=#=#

#Demande des variables
#=====================

print("IP Cible :")
ipCible = input()
print("\nPort minimum :")
pMin = input()
print("\nPort maximum :")
pMax = input()

#========SCAN UDP==========

#Pas encore developper

#========SCAN TCP SIMPLE===========
print ("\n\nSCAN TCP SIMPLE (SYN)")
print ("###############")
LeScan(pMin, pMax, 20, "S", "SIMPLE", ipCible)

#===========SCAN FIN==============
print ("\nSCAN FIN")
print ("########")
LeScan(pMin, pMax, 20, "F", "OTHER", ipCible)

#=======SCAN Maimon (FIN/ACK)=====
print ("SCAN Maimon")
print ("###########")
LeScan(pMin, pMax, 20, "FA", "OTHER", ipCible)

#==========SCAN NULL==============
print ("\nSCAN NULL")
print ("#########")
LeScan(pMin, pMax, 20, "", "OTHER", ipCible)

#==========SCAN Xmas==============
print ("\nSCAN Xmas")
print ("########")
LeScan(pMin, pMax, 20, "FPU", "OTHER", ipCible)
