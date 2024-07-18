# noinspection SpellCheckingInspection
class ClaimValueTypes:
    XmlSchemaNamespace = "http://www.w3.org/2001/XMLSchema"

    Base64Binary = XmlSchemaNamespace + "#base64Binary"
    Base64Octet = XmlSchemaNamespace + "#base64Octet"
    Boolean = XmlSchemaNamespace + "#boolean"
    Date = XmlSchemaNamespace + "#date"
    DateTime = XmlSchemaNamespace + "#dateTime"
    Double = XmlSchemaNamespace + "#double"
    Fqbn = XmlSchemaNamespace + "#fqbn"
    HexBinary = XmlSchemaNamespace + "#hexBinary"
    Integer = XmlSchemaNamespace + "#integer"
    Integer32 = XmlSchemaNamespace + "#integer32"
    Integer64 = XmlSchemaNamespace + "#integer64"
    Sid = XmlSchemaNamespace + "#sid"
    String = XmlSchemaNamespace + "#string"
    Time = XmlSchemaNamespace + "#time"
    UInteger32 = XmlSchemaNamespace + "#uinteger32"
    UInteger64 = XmlSchemaNamespace + "#uinteger64"

    SoapSchemaNamespace = "http://schemas.xmlsoap.org/"

    DnsName = SoapSchemaNamespace + "claims/dns"
    Email = SoapSchemaNamespace + "ws/2005/05/identity/claims/emailaddress"
    Rsa = SoapSchemaNamespace + "ws/2005/05/identity/claims/rsa"
    UpnName = SoapSchemaNamespace + "claims/UPN"

    XmlSignatureConstantsNamespace = "http://www.w3.org/2000/09/xmldsig#"

    DsaKeyValue = XmlSignatureConstantsNamespace + "DSAKeyValue"
    KeyInfo = XmlSignatureConstantsNamespace + "KeyInfo"
    RsaKeyValue = XmlSignatureConstantsNamespace + "RSAKeyValue"

    XQueryOperatorsNameSpace = "http://www.w3.org/TR/2002/WD-xquery-operators-20020816"

    DaytimeDuration = XQueryOperatorsNameSpace + "#dayTimeDuration"
    YearMonthDuration = XQueryOperatorsNameSpace + "#yearMonthDuration"

    Xacml10Namespace = "urn:oasis:names:tc:xacml:1.0"

    Rfc822Name = Xacml10Namespace + ":data-type:rfc822Name"
    X500Name = Xacml10Namespace + ":data-type:x500Name"
