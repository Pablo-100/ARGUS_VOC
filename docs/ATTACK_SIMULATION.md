# 🎯 Simulation d'attaque Kali → tbini (démo contrôlée)

> ⚠️ UNIQUEMENT contre vos propres machines lab (tbini = 192.168.184.138).
> Tout ce qui suit est visible dans le portail ARGUS en < 60 secondes.

## 0. Préparation Kali
Kali doit être sur le même réseau 192.168.184.x. Vérifier :
```bash
ping -c1 192.168.184.138
```

## 1. Reconnaissance — Nmap agressif
```bash
nmap -T5 -sV -O -p- 192.168.184.138
```
**Visible dans ARGUS :**
- Endpoints → « Réseau live » : les flux kali→tbini apparaissent
- Assets : l'inventaire se met à jour au prochain scan planifié

## 2. Brute force SSH — le plus spectaculaire 🎯
```bash
# dictionnaire rapide intégré à Kali
hydra -l tbini -P /usr/share/wordlists/rockyou.txt \
      -t 8 -f ssh://192.168.184.138
```
(rockyou.gz décompresser : `gunzip /usr/share/wordlists/rockyou.txt.gz`)

**Visible dans ARGUS :** Endpoints → Host=`tbini`, Type=`logins`,
Résultat=`FAILED` → **mur de FAILED en rouge, temps réel**.
Screenshot idéal pour le rapport.

## 3. Scan web (si un serveur web tourne sur tbini)
```bash
nikto -h http://192.168.184.138 -Port 80,8080
whatweb http://192.168.184.138
```

## 4. Vérification dans le portail
1. Portal → Endpoints → filtres ci-dessus
2. Portal → Activity feed (dashboard) : les événements défilent
3. GLPI/Kibana : historique complet

## 5. Après la démo — remédiation visible
Sur tbini : `sudo systemctl stop ssh` (ou fail2ban) puis re-test hydra →
les connexions sont refusées avant PAM = plus de FAILED massifs.
