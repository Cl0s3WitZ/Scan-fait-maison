# Scan de Ports avec Scapy

## Description
Ce script Python utilise la bibliothèque **Scapy** pour effectuer des scans de ports sur une cible donnée. Il permet de tester différents types de scans TCP et constitue un projet d'expérimentation avec **Scapy**.

## Fonctionnalités
- Scan TCP simple (SYN)
- Scan FIN
- Scan Maimon (FIN/ACK)
- Scan NULL
- Scan Xmas

Les ports sont scannés dans un **ordre aléatoire** afin d'éviter une détection trop facile par les mécanismes de surveillance réseau.

## Prérequis
- **Python 3**
- **Scapy** (installable avec pip) :
  ```bash
  pip install scapy
  ```

## Utilisation
1. Exécutez le script :
   ```bash
   python script.py
   ```
2. Entrez l'adresse IP de la cible et les plages de ports.
3. Laissez le scan s'exécuter et observez les résultats.

## Remarque
Ce projet est un **ancien script** utilisé pour tester **Scapy** et expérimenter différentes techniques de scan de ports. Il peut contenir des limitations et ne doit être utilisé que dans un cadre légal et avec l'autorisation des propriétaires des machines scannées.
