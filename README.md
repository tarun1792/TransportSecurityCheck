# TransportSecurityCheck
This python script allows you to check the transport security implemented in an iOS application.

## App Transport Security(ATS)

ATS requires that all HTTP connections made with the URL Loading System—typically using the URLSession class—use HTTPS. It further imposes extended security checks that supplement the default server trust evaluation prescribed by the Transport Layer Security (TLS) protocol. ATS blocks connections that fail to meet minimum security specifications.

## Possible Attacks

- ### SSL Striping
  An attacker can strip the ssl from a possible network and force the application to communicate using HTTP. which in result allows the attacker to do Man in the Middle attacks.
  
  ATS restricts the application to start communication with server in such encounters.

## Usages
```bash
python TransportSecurityCheck.py [Path of target IPA]
                        OR
python3 TransportSecurityCheck.py [Path of target IPA]
```

## Example Result

    NSAppTransportSecurity
    --------------------Result---------------------
    ===============================================
    NSAllowArbitraryLoad :  True
    ===============================================
    NSExceptionDomains : Not Specified
    
    ------------------CONCLUSION---------------------
    CONFIGURATION: FAILED (Transport security is Disabled for all domains)
    Spend time verifying:
    • The ciphers used for the app’s backend connections (and that they’re strong)
    • The protocols used to send and retrieve data (and that they’re secure)
    • Whether the app has any downgrade vulnerabilities
    • Whether the app validates certificates used for TLS connections

## License

This project is using the GNU General Public License v3.0.
