# TransportSecurityCheck
This python script allows you to check the transport security implemented in an iOS application.

## Usages

python TransportSecurityCheck.py [Path of target IPA]

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
