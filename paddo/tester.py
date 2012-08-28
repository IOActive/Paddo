#
#   Paddo 
#   Created: 01/27/2011
#   Purpose: framework for auditing and exploiting Padding Oracles vulnerabilities.
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
