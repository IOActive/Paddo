#
#   Paddo 
#
#   Created: 01/27/2011
#
#   Purpose: 
#   Audit and attack the underlying cryptography in encrypted blocks for 
#   decrypting them or re-encrypting any plaintext without knowing the 
#   secret key. An "oracle" is when a service or machine receives a ciphertext, 
#   decrypts it and then replies to the sender whether the padding is correct 
#   or not. At Eurocrypt 2002, Vaudenay introduced a powerful side-channel attack 
#   against CBC-mode encryption with PKCS#5. This framework currently attacks 
#   Java Server Faces vulnerable versions and allows to extend current methods 
#   for beeing used in customized web applications.
#
#   Copyright (c) 2012 by Lucas Apa, IOActive, Inc.
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
# 

import re, binascii


def blocksize(cipher):
    
    blocks = -1
    cipherSize = len(cipher)
    
    for x in xrange(cipherSize/8):
        
        if not len(cipher)%((x+1)*8):
            blocks = x+1
        else:
            break
        
    return cipherSize/blocks
    

def main():
    exploit = JsfExploit("", securityWord, 16)           



if __name__ == '__main__':
    main()
