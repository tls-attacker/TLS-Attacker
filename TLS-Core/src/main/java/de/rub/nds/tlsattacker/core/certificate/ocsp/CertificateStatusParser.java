/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate.ocsp;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.*;
import de.rub.nds.tlsattacker.core.util.Asn1ToolInitializer;
import java.math.BigInteger;
import java.util.List;

public class CertificateStatusParser {

    public static CertificateStatus parseCertificateStatus(Asn1Sequence certStatusSeq) {
        Asn1ToolInitializer.initAsn1Tool();
        CertificateStatus certificateStatus = new CertificateStatus();
        certificateStatus.setCertificateStatusSequence(certStatusSeq);

        String hashAlgorithmIdentifier = null;
        byte[] issuerNameHash = null;
        byte[] issuerKeyHash = null;
        BigInteger serialNumber = null;
        Integer certificateStatusValue = null;
        String revocationTime = null;
        Integer revocationReason = null;
        String timeOfLastUpdate = null;
        String timeOfNextUpdate = null;

        Asn1Sequence requestInformation = (Asn1Sequence) certStatusSeq.getChildren().get(0);

        /*
         * At first, get information about the processed request. This MAY differ from the original request sometimes,
         * as some responders don't need all values to match to give a response for a given certificate. DigiCert's OCSP
         * responder, for example, also accepts an invalid issuerKeyHash in a request if the other values match up and
         * returns the correct one in the response.
         */

        Asn1Sequence hashAlgorithmSequence = (Asn1Sequence) requestInformation.getChildren().get(0);
        hashAlgorithmIdentifier =
                (((Asn1ObjectIdentifier) hashAlgorithmSequence.getChildren().get(0)).getValue());

        // Workaround for ASN.1 Tool messing up the correct type occasionally,
        // switching between Primitive and Encapsulated
        Asn1Encodable issuerNameHashObject = requestInformation.getChildren().get(1);
        Asn1Encodable issuerKeyHashObject = requestInformation.getChildren().get(2);
        if (issuerNameHashObject instanceof Asn1PrimitiveOctetString) {
            issuerNameHash = ((Asn1PrimitiveOctetString) issuerNameHashObject).getValue();
        } else if (issuerNameHashObject instanceof Asn1EncapsulatingOctetString) {
            issuerNameHash =
                    ((Asn1EncapsulatingOctetString) issuerNameHashObject).getContent().getValue();
        }
        if (issuerKeyHashObject instanceof Asn1PrimitiveOctetString) {
            issuerKeyHash = ((Asn1PrimitiveOctetString) issuerKeyHashObject).getValue();
        } else if (issuerKeyHashObject instanceof Asn1EncapsulatingOctetString) {
            issuerKeyHash =
                    ((Asn1EncapsulatingOctetString) issuerKeyHashObject).getContent().getValue();
        }

        // Another ASN.1 Tool bug workaround: Sometimes the serial number is
        // identified as an encapsulated bit string.
        Asn1Encodable serialNumberObject = requestInformation.getChildren().get(3);
        if (serialNumberObject instanceof Asn1Integer) {
            serialNumber = ((Asn1Integer) serialNumberObject).getValue();
        } else if (serialNumberObject instanceof Asn1EncapsulatingBitString) {
            Asn1EncapsulatingBitString serialNumberBitStringObject =
                    (Asn1EncapsulatingBitString) serialNumberObject;
            serialNumber = new BigInteger(1, serialNumberBitStringObject.getContent().getValue());
        }

        /*
         * And here comes the revocation status. ASN.1 Tool has no support for parsing Implicit types yet and therefore
         * returns either Null or EndOfContent for a 'good' status, so we treat them both as good status.
         */

        Asn1Encodable certStatusObject = certStatusSeq.getChildren().get(1);

        // Good status
        if (certStatusObject instanceof Asn1Null || certStatusObject instanceof Asn1EndOfContent) {
            certificateStatusValue = 0; // good, not revoked
        } else if (certStatusObject instanceof Asn1Explicit) {
            // Time of next update (offset 0), revoked (offset 1) or unknown
            // (offset 2) status
            Asn1Explicit certStatusExplicitObject = (Asn1Explicit) certStatusObject;
            switch (certStatusExplicitObject.getOffset()) {
                case 1:
                    certificateStatusValue = 1; // revoked
                    List<Asn1Encodable> revocationObjects = certStatusExplicitObject.getChildren();
                    revocationTime =
                            ((Asn1PrimitiveGeneralizedTime) revocationObjects.get(0)).getValue();

                    // Optional revocation reason
                    if (revocationObjects.size() > 1) {
                        if (revocationObjects.get(1) instanceof Asn1Enumerated) {
                            revocationReason =
                                    ((Asn1Enumerated) revocationObjects.get(1))
                                            .getValue()
                                            .intValue();
                        }
                    }
                    break;
                case 2:
                    certificateStatusValue = 2; // unknown
                    break;
                default:
                    certificateStatusValue = 2; // unknown
                    break;
            }
        }

        // After the status comes the mandatory timeOfLastUpdate
        Asn1PrimitiveGeneralizedTime timeOfLastUpdateObject =
                (Asn1PrimitiveGeneralizedTime) certStatusSeq.getChildren().get(2);
        timeOfLastUpdate = timeOfLastUpdateObject.getValue();

        // And at last, optional tags for lastUpdate and extensions
        for (int i = 3; i < certStatusSeq.getChildren().size(); i++) {
            Asn1Encodable nextObject = certStatusSeq.getChildren().get(i);
            if (nextObject instanceof Asn1Explicit) {
                Asn1Explicit nextExplicitObject = (Asn1Explicit) nextObject;

                switch (nextExplicitObject.getOffset()) {
                    case 0:
                        timeOfNextUpdate =
                                ((Asn1PrimitiveGeneralizedTime)
                                                nextExplicitObject.getChildren().get(0))
                                        .getValue();
                        break;
                    case 1:
                        // TODO: Add support for singleExtensions here.
                        break;
                    default:
                        // TODO: Add support for singleExtensions here.
                        break;
                }
            }
        }

        // Set fields in generated CertificateStatus object
        certificateStatus.setHashAlgorithmIdentifier(hashAlgorithmIdentifier);
        certificateStatus.setIssuerNameHash(issuerNameHash);
        certificateStatus.setIssuerKeyHash(issuerKeyHash);
        certificateStatus.setSerialNumber(serialNumber);
        certificateStatus.setCertificateStatus(certificateStatusValue);
        certificateStatus.setRevocationTime(revocationTime);
        certificateStatus.setRevocationReason(revocationReason);
        certificateStatus.setTimeOfLastUpdate(timeOfLastUpdate);
        certificateStatus.setTimeOfNextUpdate(timeOfNextUpdate);

        return certificateStatus;
    }
}
