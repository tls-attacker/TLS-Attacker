/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.certificate.ocsp;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.*;
import de.rub.nds.asn1.parser.Asn1Parser;
import de.rub.nds.asn1.parser.ParserException;
import de.rub.nds.asn1.parser.contentunpackers.ContentUnpackerRegister;
import de.rub.nds.asn1.parser.contentunpackers.DefaultContentUnpacker;
import de.rub.nds.asn1.parser.contentunpackers.PrimitiveBitStringUnpacker;
import de.rub.nds.asn1.translator.ContextRegister;
import de.rub.nds.asn1.translator.ParseNativeTypesContext;
import de.rub.nds.asn1.translator.ParseOcspTypesContext;
import org.bouncycastle.asn1.x509.Certificate;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

public class CertificateInformationExtractor {

    Certificate cert;
    static boolean asn1ToolInitialized = false;

    public CertificateInformationExtractor(Certificate cert) {
        this.cert = cert;

        // Init ASN.1 Tool
        if (!asn1ToolInitialized) {
            registerContexts();
            registerContentUnpackers();
            asn1ToolInitialized = true;
        }
    }

    public BigInteger getSerialNumber() {
        return cert.getSerialNumber().getValue();
    }

    public byte[] getIssuerNameHash() throws IOException, NoSuchAlgorithmException {
        byte[] encodedDistinguishedName = cert.getIssuer().getEncoded();
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(encodedDistinguishedName);
    }

    public byte[] getIssuerKeyHash() throws IOException, NoSuchAlgorithmException {
        byte[] publicKey = cert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(publicKey);
    }

    public String getOcspServerUrl() throws IOException, ParserException, NullPointerException {

        /*
         * TODO: Needs cleanup and a sanity check! This is kind of a messy way
         * to go through the ASN.1 structure, but it works surprisingly well...
         * If you're trying to understand the way this works, open up an ASN.1
         * decoder next to the code and go through it hierarchically.
         */

        String ocspUrlResult = null;

        byte[] certAsn1 = cert.getEncoded();

        // Parse ASN.1 structure of the certificate
        Asn1Parser asn1Parser = new Asn1Parser(certAsn1, false);
        List<Asn1Encodable> asn1Encodables = asn1Parser.parse(ParseOcspTypesContext.NAME);

        // Navigate through the mess to the OCSP URL. First, just unroll the
        // two outer ASN.1 sequences to get to most of the information
        // stored in a X.509 certificate.
        Asn1Sequence innerObjects = (Asn1Sequence) ((Asn1Sequence) asn1Encodables.get(0)).getChildren().get(0);

        // Get sequence containing X.509 extensions
        Asn1Sequence x509Extensions = null;

        for (Asn1Encodable enc : innerObjects.getChildren()) {
            if (enc instanceof Asn1Sequence) {
                if (((Asn1Sequence) enc).getIdentifierOctets().getOriginalValue().length > 0) {
                    // -93 == 0xA3 signed. It's the explicit tag for X.509
                    // extension in the DER encoded form, therefore a good
                    // value to search for.
                    if (((Asn1Sequence) enc).getIdentifierOctets().getOriginalValue()[0] == -93) {
                        x509Extensions = (Asn1Sequence) enc;
                        break;
                    }
                }
            }
        }

        // Now that we found the extensions, search for the
        // 'authorityInfoAccess' extension
        List<Asn1Encodable> x509ExtensionsSequences = ((Asn1Sequence) x509Extensions.getChildren().get(0))
                .getChildren();
        Asn1Sequence authorityInfoAccess = null;
        for (Asn1Encodable enc : x509ExtensionsSequences) {
            if (enc instanceof Asn1Sequence) {
                Asn1ObjectIdentifier objectIdentifier = (Asn1ObjectIdentifier) (((Asn1Sequence) enc).getChildren()
                        .get(0));
                // This is the objectIdentifier value for
                // authorityInfoAccess
                if (objectIdentifier.getValue().equals("1.3.6.1.5.5.7.1.1")) {
                    authorityInfoAccess = (Asn1Sequence) enc;
                }
            }
        }

        // get(0) is the Object Identifier we checked, get(1) the Octet
        // String with the content
        // The Octet String has a sequence as child, and one of them has
        // the desired OCSP information.
        // Almost there!
        Asn1EncapsulatingOctetString authorityInfoAccessEntities = (Asn1EncapsulatingOctetString) authorityInfoAccess
                .getChildren().get(1);
        Asn1Sequence authorityInfoAccessEntitiesSequence = (Asn1Sequence) authorityInfoAccessEntities.getChildren()
                .get(0);

        List<Asn1Encodable> ocspInformation = null;

        // Now let's check if we have OCSP information embedded...
        for (Asn1Encodable enc : authorityInfoAccessEntitiesSequence.getChildren()) {
            if (enc instanceof Asn1Sequence) {
                Asn1ObjectIdentifier objectIdentifier = (Asn1ObjectIdentifier) ((Asn1Sequence) enc).getChildren()
                        .get(0);
                // This is the objectIdentifier value for OCSP
                if (objectIdentifier.getValue().equals("1.3.6.1.5.5.7.48.1")) {
                    ocspInformation = ((Asn1Sequence) enc).getChildren();
                    break;
                }
            }
        }

        // If we found the OCSP information, let's extract it and we're
        // done!
        if (ocspInformation != null) {
            Asn1PrimitiveIa5String ocspUrlIa5String = null;
            if (ocspInformation.size() > 1 && ocspInformation.get(1) instanceof Asn1PrimitiveIa5String) {
                ocspUrlIa5String = (Asn1PrimitiveIa5String) ocspInformation.get(1);
            }
            ocspUrlResult = ocspUrlIa5String.getValue();
        }

        return ocspUrlResult;
    }

    private static void registerContexts() {
        ContextRegister contextRegister = ContextRegister.getInstance();
        contextRegister.registerContext(ParseNativeTypesContext.NAME, ParseNativeTypesContext.class);
        contextRegister.registerContext(ParseOcspTypesContext.NAME, ParseOcspTypesContext.class);
    }

    private static void registerContentUnpackers() {
        ContentUnpackerRegister contentUnpackerRegister = ContentUnpackerRegister.getInstance();
        contentUnpackerRegister.registerContentUnpacker(new DefaultContentUnpacker());
        contentUnpackerRegister.registerContentUnpacker(new PrimitiveBitStringUnpacker());
    }
}
