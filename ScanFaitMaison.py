#! /usr/bin/python

from scapy.all import *
import random

#==========FONCTIONS==============
def randomPorts(pMin, pMax, num_ranges):
    range_list = [(i, i + num_ranges - 1) for i in range(pMin, pMax + 1, num_ranges)]
    random.shuffle(range_list)
    return range_list

#===========SCAN TCP=============
def leScan(pMin, pMax, num_ranges, lesFlags, typeScan, ipCible):
    listePorts = randomPorts(pMin, pMax, num_ranges)
    print("\nScan en cours...")
    listePortsOuverts = []
    listePortsFermes = []

    #--------------Envoi des paquets----------------
    for i in listePorts:
        trame = Ether()/IP(dst=ipCible)/TCP(sport=57915, dport=i, flags=lesFlags)
        reponse = srp(trame, timeout=1, verbose=False)

        #-------------------------Récupération des réponses----------------------------
        for y in range(len(reponse[0])):
            reponseFlags = (reponse[0][y][1].getlayer(TCP).flags)
            reponsePort = (reponse[0][y][1].getlayer(TCP).sport)
            if reponseFlags != "RA":
                listePortsOuverts.append((reponsePort, reponseFlags))
            if reponseFlags == "RA" or reponseFlags == "R":
                listePortsFermes.append(reponsePort)

    #---------------------------Analyse des réponses--------------------------------
    print("\nLa liste des ports ouverts : ")
    for r1 in listePortsOuverts:
        print("port =", r1[0], " ----------> réponse =", r1[1])
    if listePortsFermes == []:
        print("Machine non vulnérable au scan")
    else:
        print("\nLa liste des ports potentiellement ouverts : ")
        for r2 in range(pMin, pMax):
            if r2 not in listePortsFermes:
                print("port =", r2)

#=============SCAN UDP=======================

#ToDo

#=#=#=#=#=#=#=#=#=#=LANCEMENT DU SCAN=#=#=#=#=#=#=#=#=#=#=#=#

#Demande des variables
#=====================

print("IP Cible :")
ipCible = input()
print("\nPort minimum :")
pMin = int(input())
print("\nPort maximum :")
pMax = int(input())

#========SCAN UDP==========

#ToDo

#========SCAN TCP SIMPLE===========
print("\n\nSCAN TCP SIMPLE (SYN)")
print("#####################")
leScan(pMin, pMax, 20, "S", "SIMPLE", ipCible)

#===========SCAN FIN==============
print("\nSCAN FIN")
print("########")
leScan(pMin, pMax, 20, "F", "OTHER", ipCible)

#=======SCAN Maimon (FIN/ACK)=====
print("SCAN Maimon")
print("###########")
leScan(pMin, pMax, 20, "FA", "OTHER", ipCible)

#==========SCAN NULL==============
print("\nSCAN NULL")
print("#########")
leScan(pMin, pMax, 20, "", "OTHER", ipCible)

#==========SCAN Xmas==============
print("\nSCAN Xmas")
print("########")
leScan(pMin, pMax, 20, "FPU", "OTHER", ipCible)

