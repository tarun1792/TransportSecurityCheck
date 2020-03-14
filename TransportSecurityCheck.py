import sys
import zipfile
import plistlib
import os

class IpaAnalyzer:

    def __init__(self,ipaName):
        self.ipaName = ipaName
        self.extractInfo()

    def prRed(self,skk):
        print("\033[91m{}\033[00m" .format(skk))

    def prGreen(self,skk):
        print("\033[92m{}\033[00m" .format(skk))

    #unzip the Ipa file
    def extractInfo(self):
            dictionary = self.getPlistFile()

            transportSecurity = dictionary.get('NSAppTransportSecurity')
            
            if transportSecurity is not None:
                self.checkConfiguration(transportSecurity)
            else:
                print('CONFIGURATION: PASSED (By Default the Transport security is Turned on)')

    # get plist file from the ipa
    def getPlistFile(self):
        #unziping IPA...
        unzippedIPA = zipfile.ZipFile(self.ipaName)
        infoPlistPath = unzippedIPA.namelist()[1]+'Info.plist'
    
        with unzippedIPA.open(infoPlistPath,'r') as plist:
            #Opening plist file
            plistDic = plistlib.load(plist)

            #Closing the plist file'
            plist.close()  

            #return plist dictionary
            return plistDic 

    # Analyiz Transport settings 
    def checkConfiguration(self,transportSecurity):
        print('\nNSAppTransportSecurity')
        print('--------------------Result---------------------')
        self.checkArbitraryLoadPermission(transportSecurity)
        self.checkExceptionDomainSettings(transportSecurity) 

    #check arbitrary load (independent)
    def checkArbitraryLoadPermission(self,transportSecurity):
        allowArbitraryLoad = transportSecurity.get('NSAllowsArbitraryLoads')
        if allowArbitraryLoad is not None:
            self.allowArbitraryLoad = allowArbitraryLoad
            print('===============================================')
            print('NSAllowArbitraryLoad : ',allowArbitraryLoad)
            print('===============================================')
        else:
            print('===============================================')
            print('NSAllowArbitraryLoad : False (Default)')
            print('===============================================')
            self.allowArbitraryLoad = False

    #check exception domains based on arbitrary load (dependent on arbiraty loads)
    def checkExceptionDomainSettings(self,transportSecurity):
        exceptionDomainsDic = transportSecurity.get('NSExceptionDomains')
        self.exceptionURLS = []
        self.includingAllSubdomains = []
        if exceptionDomainsDic is not None:
            for key,val in exceptionDomainsDic.items():
                
                self.printConfiguration(key,val)

                if len(exceptionDomainsDic) == len(self.exceptionURLS):
                    self.printSuggestion(True,self.checkIncludeSubdomainsSetting(val))
                else:
                    print('--------------------------------------------------')

        else:
            print('NSExceptionDomains : Not Specified')
            self.printSuggestion(False,False)

    def printConfiguration(self,key,val):
        self.checkExceptionDoaminUrl(key)
        print('NSIncludesSubdomains : ',self.checkIncludeSubdomainsSetting(val))
        print('NSTemporaryExceptionAllowsInsecureHTTPLoads : ',self.checkAllowInsecureHTTPLoads(val))
        print('NSExceptionMinimumTLSVersion : ',self.checkMinimumTlsVersion(val))
        print('NSExceptionRequiresForwardSecrecy : ',self.checkForwardSecrecy(val))
        print('NSRequiresCertificatesTransparency : ',self.checkRequiresCertificatesTransparency(val))


    def checkExceptionDoaminUrl(self,value):
        message = '(Transport security is ENABLED for this domain)'
        self.exceptionURLS.append(value)
        if self.allowArbitraryLoad == False:
                message = '(Transport security is DISABLED for this domain)'
        print("NSExceptionDomains : ",value, "" , message)

    #check include subdomains (dependent on arbitrary load)
    def checkIncludeSubdomainsSetting(self,exceptionDomainsDic):
        includeSubdomains = exceptionDomainsDic.get('NSIncludesSubdomains')
        
        if includeSubdomains is not None:
            if self.allowArbitraryLoad == True:
                self.includingAllSubdomains.append(includeSubdomains)
                return includeSubdomains
            elif self.allowArbitraryLoad == False:
                self.includingAllSubdomains.append(not includeSubdomains)
                return not includeSubdomains   
        else:
            self.includingAllSubdomains.append(includeSubdomains)
           # 'NSIncludesSubdomains : False (default)'
            return True

    #check allows insecure HTTP loads (independent) : default - No
    def checkAllowInsecureHTTPLoads(self,exceptionDomainsDic):
        allowInsecureHttpLoads = exceptionDomainsDic.get('NSTemporaryExceptionAllowsInsecureHTTPLoads')
        if allowInsecureHttpLoads is not None:  
            return allowInsecureHttpLoads 
        else:
            #'NSTemporaryExceptionAllowsInsecureHTTPLoads : False (Default)')
            return 'False (Default)'

    #check minimum tls version (independent) : default - 1.2
    def checkMinimumTlsVersion(self,exceptionDomainsDic):
        minimumTLSVersion = exceptionDomainsDic.get('NSExceptionMinimumTLSVersion')
        if minimumTLSVersion is not None:
            return minimumTLSVersion   
        else:
            #NSExceptionMinimumTLSVersion : 1.2 (Default)
            return '1.2 (Default)'

    #check forwards secrecy (independent) : default - Yes
    def checkForwardSecrecy(self,exceptionDomainsDic):
        requireForwardSecrecy = exceptionDomainsDic.get('NSExceptionRequiresForwardSecrecy')
        if requireForwardSecrecy is not None: 
            return requireForwardSecrecy  
        else:
            #NSExceptionRequiresForwardSecrecy : True (Default)
            return 'True (Default)'

    #check certificates transparency  (independent) default - No
    def checkRequiresCertificatesTransparency(self,exceptionDomainsDic):
        requiresCertificatesTransparency = exceptionDomainsDic.get('NSRequiresCertificatesTransparency')
        if requiresCertificatesTransparency is not None: 
            return requiresCertificatesTransparency  
        else:
            #NSRequiresCertificatesTransparency : False (Default)   
            return 'False (Default)'     

             

    def printSuggestion(self,exceptionDomain,includeSubDomains):
        
        if exceptionDomain == False:
            if self.allowArbitraryLoad == True:
                print("\n------------------CONCLUSION---------------------")
                self.prRed('CONFIGURATION: FAILED (Transport security is Disabled for all domains)')
                self.prRed('''Spend time verifying:
    • The ciphers used for the app’s backend connections (and that they’re strong)
    • The protocols used to send and retrieve data (and that they’re secure)
    • Whether the app has any downgrade vulnerabilities
    • Whether the app validates certificates used for TLS connections''')
            elif self.allowArbitraryLoad == False:            
                print("\n------------------CONCLUSION---------------------")
                self.prGreen('CONFIGURATION: PASSED (Transport security is Enabled for all URLS)')

        elif exceptionDomain == True and self.allowArbitraryLoad == True:
            print("\n------------------CONCLUSION---------------------")
            self.prGreen('''CONFIGURATION: PASSED (Transport security is Disabled for all URLS)''')
            print("Except for URL: ")
            self.printSubDomains()
        elif exceptionDomain == True and self.allowArbitraryLoad == False:
            print("\n------------------CONCLUSION---------------------")
            self.prGreen('''CONFIGURATION: PASSED (Transport security is Enabled for all URLS)''')
            print("Except for URL: ")
            self.printSubDomains()
            self.prRed('''Spend time verifying below points for urls:
    • The ciphers used for the app’s backend connections (and that they’re strong)
    • The protocols used to send and retrieve data (and that they’re secure)
    • Whether the app has any downgrade vulnerabilities
    • Whether the app validates certificates used for TLS connections''')           

    #Prints all subdomains and their respective inclution
    def printSubDomains(self):
        expectionstring = ""
        for i in range(0,len(self.exceptionURLS)):
            includSub = self.includingAllSubdomains[i]
            subdomainsmsg = 'including all subdomains'
            if includSub == False:
                subdomainsmsg = 'Excluding all subdomains'

            expectionstring += "                 " + self.exceptionURLS[i] + " --> " + subdomainsmsg + "\n"

        print(expectionstring)


    

if len(sys.argv) > 1:
    path = sys.argv[1]
    IPA = path.split("/")[-1]
    ipa = IpaAnalyzer(IPA)

else:
    print("""
===================USAGES==============================
python TransportSecurityCheck.py [IPA_Path]
                OR
python3 TransportSecurityCheck.py [IPA_Path] 
    """)
