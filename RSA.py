
# Comment utiliser le programme :  
#                                   1) choisissez le mode de génération de n ou de choisir (p, q) (1 ou 2) 
#                                   2) Choisissez de générer e automatiquement ou de l'entrer manuellement  
#                                   3) Choisissez de crypter, décrypter ou signer/vérifier (c/d/s/v)  
#                                   4) Le message original est lu depuis "message.txt" pour le cryptage ou la signature,  
#                                      et le message chiffré est lu depuis "message_crypte.txt" pour le décryptage,  
#                                      ou depuis "signature.txt" pour la vérification de signature.  
#                                   5) Les résultats seront écrits dans "message_crypte.txt" (chiffré),  
#                                      "message_decrypte.txt" (déchiffré), ou "signature.txt" (signature).

######### NOTE: vous devez avoir le fihier "message.txt", "signature.txt" dans le même répertoire que ce programe, pour que le programme fonctionne correctement.
#       et dans ce fichier vous insertez le message que vous voulez crypter ou signer, les autres fichiers seront générés automatiquement, dapres lui

#----------------------------------------------------------------------------------------------------------------------------------------------------------
import math

#----------------------------------------------------------------------------------------------------------------------------------------------------------
# Fonction de hachage simple pour signature : somme des codes ASCII, puis mise au carré

def hachage(chaine):
    res = 0
    for c in chaine:
        res += ord(c)
    return res ** 2

#----------------------------------------------------------------------------------------------------------------------------------------------------------
#signer un message (hachage du message, puis application de la clé privée)
def signer_message(message, d, n):
    h = hachage(message)
    return pow(h % n, d, n)

#----------------------------------------------------------------------------------------------------------------------------------------------------------
# vérifier une signature (comparaison entre hachage local et hachage déchiffré avec la clé publique)
def verifier_signature(message, signature, e, n):
    h1 = hachage(message) % n
    h2 = pow(signature, e, n)
    return h1 == h2

#----------------------------------------------------------------------------------------------------------------------------------------------------------
# crypter un message 
def crypter_RSA(chaine, p, q, e):
    n = p * q                                            # calcul du module n
    chaine_cryptee = ""                                 # contiendra le message chiffré
    for lettre in chaine:                                 # itération sur chaque caractère
        asc = ord(lettre)                                 # conversion en code ASCII
        if asc >= n:
            raise ValueError(f"Le code ASCII {asc} est trop grand pour n={n}")
        i = pow(asc, e, n)                                # chiffrement : (ASCII^e) mod n
        chaine_cryptee += chr(i)                          # conversion en caractère et ajout
    return chaine_cryptee                                 # retourne la chaîne chiffrée

#----------------------------------------------------------------------------------------------------------------------------------------------------------
# décrypter un message 
def decrypter_RSA(chaine, p, q, d):
    n = p * q                                            # calcul du module n
    chaine_decryptee = ""                               # contiendra le message déchiffré
    for lettre in chaine:                                 # itération sur chaque caractère chiffré
        asc = ord(lettre)                                 # conversion en code ASCII
        i = pow(asc, d, n)                                # déchiffrement : (ASCII^d) mod n
        chaine_decryptee += chr(i)                        # conversion en caractère et ajout
    return chaine_decryptee                              # retourne la chaîne déchiffrée

#----------------------------------------------------------------------------------------------------------------------------------------------------------
# Calcule de la clé privée d
def calcule_D(p, q, e):
    phi = (p - 1) * (q - 1)                               # phi(n) = (p-1)*(q-1)
    try:
        d = pow(e, -1, phi)                              # inverse modulaire de e mod phi
        return d                                        # retourne d
    except ValueError:
        raise Exception("Impossible de calculer la clé privée d.")

#----------------------------------------------------------------------------------------------------------------------------------------------------------
# Calcule un exposant public e valide

def calcule_e(p, q):
    phi = (p - 1) * (q - 1)                               # phi(n)
    e = 2
    while math.gcd(e, phi) != 1:
        e += 1
    return e                                             # retourne le premier e valide

#----------------------------------------------------------------------------------------------------------------------------------------------------------
# Vérifie si un nombre est premier  ( on va lutiliser pour générer p et q automatiquement )
def est_premier(n):
    if n < 2:
        return False                                    # aucun nombre < 2 n'est premier
    for p in [2,3,5,7,11,13,17,19,23,29,31]:
        if n % p == 0:
            return n == p                              # vrai si égal à cette base
    d, s = n-1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in [2,325,9375,28178,450775,9780504,1795265022]:
        if a >= n:
            continue
        x = pow(a, d, n)
        if x in (1, n-1):
            continue
        for _ in range(s-1):
            x = pow(x, 2, n)
            if x == n-1:
                break
        else:
            return False
    return True                                        # n est premier

#----------------------------------------------------------------------------------------------------------------------------------------------------------
# Génération automatique de p et q à partir d'une valeur  n

def generer_p_q_depuis_n(n):
    # Recherche de deux nombres premiers p et q tels que p * q <= n
    candidats = [i for i in range(2, n) if est_premier(i)]
    # On parcourt les p du plus grand au plus petit pour s'approcher de n
    for p in reversed(candidats):
        for q in candidats:
            if p != q and p * q <= n:
                return p, q
    raise Exception("Impossible de trouver deux nombres premiers p et q pour ce n.")

#----------------------------------------------------------------------------------------------------------------------------------------------------------


#----------------------------------------------------------------------------------------------------------------------------------------------------------
# Cherche p et q tels que p * q == n, et tous deux premiers
def trouver_p_q_depuis_n(n):
    for p in range(2, n):
        if est_premier(p) and n % p == 0:
            q = n // p
            if est_premier(q) and p != q:
                return p, q
    raise Exception("Aucun couple (p, q) premier trouvé tel que p * q = n.")

#----------------------------------------------------------------------------------------------------------------------------------------------------------
def main():
    print("\n--- Système de chiffrement RSA avec Signature ---\n")

    # Choix du mode de génération de n, p, q
    while True:
        mode = input("Choisissez le mode :\n1. Entrer une valeur n pour générer p et q\n2. Entrer directement une valeur de p ,q\nChoix (1/2): ")
        if mode == "1":
            try:
                n_val = int(input("Entrez une valeur pour n (produit de deux nombres premiers) : "))
                if n_val < 10:
                    print("n doit être plus grand (au moins 10).")
                    continue
                p, q = generer_p_q_depuis_n(n_val)
                print(f"p généré automatiquement : {p}")
                print(f"q généré automatiquement : {q}")
                break
            except ValueError:
                print("Entrée invalide. Veuillez entrer un entier.")
            except Exception as e:
                print(str(e))
        elif mode == "2":
            try:
                p = int(input("Entrez la valeur de q  : "))
                q= int(input("Entrez la valeur de p  : "))
                n = p*q
            
                if( not(est_premier(p) and est_premier(q))):
                        print("ERReur ")
                        return
                       


                    
                break
            except ValueError:
                print("Entrée invalide. Veuillez entrer un entier.")
            except Exception as e:
                print(str(e))
        else:
            print("Choix invalide. Veuillez entrer 1 ou 2.")

    phi = (p - 1) * (q - 1)  # phi(n)

    # Choix de l'exposant e
    while True:
        choix = input("Voulez-vous: \n1. Générer e automatiquement\n2. Entrer e manuellement\nChoix (1/2): ")
        if choix == "1":
            e = calcule_e(p, q)
            print(f"e généré automatiquement: {e}")
            break
        elif choix == "2":
            e = int(input("Entrez la valeur de e : "))
            if e <= 1 or e >= phi or math.gcd(e, phi) != 1:
                print(f"e doit être >1, <{phi} et premier avec phi(n).")
                continue
            break
        else:
            print("Choix invalide. Veuillez entrer 1 ou 2.")

    d = calcule_D(p, q, e)
    n = p * q

    action = input("Voulez-vous crypter, decrypter, signer ou verifier (c/d/s/v) ? ").lower()

    if action == "c":
        with open("message.txt","r",encoding="utf-8") as f:
            chaine = f.read()
        chaine_cryptee = crypter_RSA(chaine,p,q,e)
        with open("message_crypte.txt","w",encoding="utf-8") as f:
            f.write(chaine_cryptee)
        print("Chaîne chiffrée écrite dans 'message_crypte.txt'.")

    elif action == "d":
        with open("message_crypte.txt","r",encoding="utf-8") as f:
            chaine = f.read()
        chaine_decryptee = decrypter_RSA(chaine,p,q,d)
        with open("message_decrypte.txt","w",encoding="utf-8") as f:
            f.write(chaine_decryptee)
        print("Chaîne déchiffrée écrite dans 'message_decrypte.txt'.")

    elif action == "s":
        with open("message.txt", "r", encoding="utf-8") as f:
            message = f.read()
        signature = signer_message(message, d, n)
        with open("signature.txt", "w", encoding="utf-8") as f:
            f.write(str(signature))
        print("Signature enregistrée dans 'signature.txt'.")

    elif action == "v":
        with open("message.txt", "r", encoding="utf-8") as f:
            message = f.read()
        with open("signature.txt", "r", encoding="utf-8") as f:
            signature = int(f.read())
        if verifier_signature(message, signature, e, n):
            print("\n--- La signature est VALIDE ---\n")
        else:
            print("\n>>> La signature n'est PAS valide <<<\n")

    else:
        print("Action invalide. Veuillez choisir 'c', 'd', 's' ou 'v'.")

#----------------------------------------------------------------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    main()
