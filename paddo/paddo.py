#!/usr/bin/env python

#
#   Paddo 
#
#   Created: 01/27/2011
#
#   Purpose: framework for auditing and conducting "padding oracle" attacks
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

import getopt, sys
import audit, jsf_exploit

def help():
    pass

def main(argv):
    try:
        opts, args = getopt.getopt(argv, "t:dp:ep:v:h", ["target", "parameter=", "encrypt=", "viewState", "help", "decrypt"])
        
    except getopt.GetoptError:          
        help()                         
        sys.exit(2)
    
    for opt, arg in opts:
        if opt in ("-t", "--target", ""):
            auditObj = audit.Audit(arg)
            auditExp = ""
            
        elif opt in ("-h", "--help"):
            help()                     
            sys.exit()
            
        if opt in ('-v', "--viewState"):
            if auditObj.jsf_viewstate():
                exploitObj = jsf_exploit.JsfExploit(auditObj)
                exploitObj.exploit_viewstate()
        
        
        if opt in ('-p', "--parameter"):           
            auditExp = auditObj.audit_param(arg)
                
                
        if opt in ('-e', "--encrypt"):
            if auditExp:
                exploitObj = jsf_exploit.JsfExploit(auditObj)
                exploitObj.encrypt_param(arg)
        
        if opt in ('-d', "--decrypt"):
            if auditExp:
                exploitObj = jsf_exploit.JsfExploit(auditObj)
                exploitObj.exploit_param()

        
def help():
    print """
    Usage: paddo [TARGET] [OPTIONS]
    
    -t TARGET           : URL Target
    
    -p PARAMETER        : Ciphertext parameter
    -e ENCRYPT_VALUE    : Value to encrypt (P.o.C)
    --decrypt           : Decrypt ciphertext
    --viewState         : Decrypt viewstate (no parameters required)
    --help              : Usage
    """


if __name__ == '__main__':
    print """                                                      
*******************************************
*       ____  ____ _____/ /___/ /___      *
*      / __ \/ __ `/ __  / __  / __ \     *
*     / /_/ / /_/ / /_/ / /_/ / /_/ /     *
*    / .___/\__,_/\__,_/\__,_/\____/      *   
*   /_/                                   *
*           Lucas Apa - IOActive	  *
*         lucas.apa@ioactive.com          *
*******************************************
_________________________________________________

Special Thanks: 
   Serge Vaudenay - Juliano Rizzo - Thai Duong
 Brian Holyfield - Nicolas Waisman - Matias Soler
_________________________________________________
    """
    main(sys.argv[1:])


