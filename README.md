Paddo
=====

Audit and attack the underlying cryptography in encrypted blocks to
decrypt them or re-encrypt any plaintext without knowing the key. An
"oracle" is when a service receives a ciphertext, decrypts it and then
replies to  the sender whether the padding is correct or not. This
allows the attack.

For example:

http://[EXAMPLE_WEBSITE]/bzJApp/Captcha.action?securityWord=OdXdV/96yBv1hA2cfGnmFFsPhYFi2xCO

Here the ciphertext is: OdXdV/96yBv1hA2cfGnmFFsPhYFi2xCO (Which inside
has the real value of the captcha)

Paddo response: [!] Plaintext: 05190,ZRFXW


2) Paddo attemps to decrypt valid ciphertext on a service which acts as
an "oracle". Obviously this service must know the key of the ciphertext
since is the one who will check for proper padding after decrypting it.

Also paddo supports re-encryption, that is encrypting a custom plaintext
with the server key without knowing it. For example encrypting a "LUCAS"
with paddo:

http://[EXAMPLE_WEBSITE]/bzJApp/Captcha.action?securityWord=XYnwj4M6c4UrXIdL0clBkQAAAAAAAAAA


This is the core of
http://technet.microsoft.com/en-us/security/bulletin/MS10-070.

Where you can encrypt a "web.config" string with the server key, and
then feed the WebResource.axd script for fetching the content of that
file. Currently paddo only attacks Java Server Faces, but it may be
extended to also support ASP.NET since the attack is very similar.

