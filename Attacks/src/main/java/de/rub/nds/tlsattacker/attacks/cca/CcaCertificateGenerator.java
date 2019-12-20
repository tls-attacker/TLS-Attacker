/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.cca;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.*;
import de.rub.nds.asn1.parser.Asn1Parser;
import de.rub.nds.asn1.parser.ParserException;
import de.rub.nds.asn1.translator.ParseNativeTypesContext;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.delegate.CcaDelegate;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificatePair;

import javax.security.auth.x500.X500Principal;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import static de.rub.nds.x509attacker.X509Attacker.*;

public class CcaCertificateGenerator {

    /**
     *
     * @param ccaDelegate
     * @param type
     * @return TODO: I might need access to a trust store. Or seperate
     *         directories for keys and certificates. It's likely that TODO: any
     *         integration of multiple certificates, partially with keys, will
     *         be implemented with x509 attacker.
     */
    public static CertificateMessage generateCertificate(CcaDelegate ccaDelegate, CcaCertificateType type) {
        CertificateMessage certificateMessage = new CertificateMessage();
        if (type != null) {
            switch (type) {
                case CLIENT_INPUT:
                    List<CertificatePair> certificatePairsList = new LinkedList<>();
                    CertificatePair certificatePair = new CertificatePair(ccaDelegate.getClientCertificate());
                    certificatePairsList.add(certificatePair);
                    certificateMessage.setCertificatesList(certificatePairsList);
                    break;
                case EMPTY:
                    certificateMessage.setCertificatesListBytes(Modifiable.explicit(new byte[0]));
                    break;
                case LEAF_RSA:

                default:
                    break;
            }
        }
        return certificateMessage;
    }

    private static CertificateMessage generateCertificateMessageFromXML(String rootCertificate, String certificateChain) {

        return new CertificateMessage();
    }

    private static String extractXMLCertificateSubject(String rootCertificate) throws CertificateException, IOException, ParserException {
        // Register XmlClasses, Types, Contexts and Unpackers
        registerXmlClasses();
        registerTypes();
        registerContexts();
        registerContentUnpackers();

        // Load X.509 root certificate and get Subject principal
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        FileInputStream fileInputStream = new FileInputStream(rootCertificate);
        X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
        X500Principal x500PrincipalSubject = x509Certificate.getSubjectX500Principal();

        // Get ASN.1 Subject
        Asn1Parser asn1Parser = new Asn1Parser(x500PrincipalSubject.getEncoded(), false);
        List<Asn1Encodable> asn1SubjectEncodables = asn1Parser.parse(ParseNativeTypesContext.NAME);

        // Loop variables
        Integer i = 0;
        Asn1Sequence _asn1Sequence;
        Asn1Encodable _asn1Encodable;
        Asn1ObjectIdentifier _asn1ObjectIdentifier;
        Asn1PrimitiveIa5String _asn1PrimitiveIa5String;
        Asn1PrimitivePrintableString _asn1PrimitivePrintableString;
        Asn1PrimitiveUtf8String _asn1PrimitiveUtf8String;

        // Output String
        StringBuilder stringBuilder = new StringBuilder();

        // Loop through parsed subject and construct XML String
        Asn1Sequence asn1Sequence = (Asn1Sequence) asn1SubjectEncodables.get(0);
        stringBuilder.append("<asn1Sequence identifier=\"issuer\" type=\"Name\">");
        stringBuilder.append("<asn1Set identifier=\"relativeDistinguishedName0\" type=\"RelativeDistinguishedName\">");
        for(Asn1Encodable asn1Set : asn1Sequence.getChildren()) {
            _asn1Sequence = (Asn1Sequence)((Asn1Set) asn1Set).getChildren().get(0);
            stringBuilder.append("<asn1Sequence identifier=\"attributeTypeAndValue" + i +"\" type=\"AttributeTypeAndValue\">");
            stringBuilder.append("<asn1ObjectIdentifier identifier=\"type\" type=\"AttributeType\">");

            _asn1ObjectIdentifier = (Asn1ObjectIdentifier) _asn1Sequence.getChildren().get(0);
            stringBuilder.append("<value>" + new StringBuilder(_asn1ObjectIdentifier.getValue().substring(0, 3)).reverse().toString() + _asn1ObjectIdentifier.getValue().substring(3) + "</value>");
            stringBuilder.append("</asn1ObjectIdentifier>");

            _asn1Encodable = _asn1Sequence.getChildren().get(1);
            if (_asn1Encodable instanceof Asn1PrimitiveUtf8String) {
                stringBuilder.append("<asn1PrimitiveUtf8String identifier=\"value\" type=\"AttributeValue\">");
                stringBuilder.append("<value>" + ((Asn1PrimitiveUtf8String) _asn1Encodable).getValue() + "</value>");
                stringBuilder.append("</asn1PrimitiveUtf8String>");

            } else if (_asn1Encodable instanceof Asn1PrimitivePrintableString) {
                stringBuilder.append("<asn1PrimitivePrintableString identifier=\"value\" type=\"AttributeValue\">");
                stringBuilder.append("<value>" + ((Asn1PrimitivePrintableString) _asn1Encodable).getValue() + "</value>");
                stringBuilder.append("</asn1PrimitivePrintableString>");
            } else if (_asn1Encodable instanceof Asn1PrimitiveIa5String) {
                stringBuilder.append("<asn1PrimitiveIa5String identifier=\"value\" type=\"AttributeValue\">");
                stringBuilder.append("<value>" + ((Asn1PrimitiveIa5String) _asn1Encodable).getValue() + "</value>");
                stringBuilder.append("</asn1PrimitiveIa5String>");
            } else {
                throw new ParserException("Parsing failed, encountered unknown Asn1 type in Subject value");
            }
            stringBuilder.append("</asn1Sequence>");
            i = i + 1;
        }
        stringBuilder.append("</asn1Set>");
        stringBuilder.append("</asn1Sequence>");

        return stringBuilder.toString();
    }

}
