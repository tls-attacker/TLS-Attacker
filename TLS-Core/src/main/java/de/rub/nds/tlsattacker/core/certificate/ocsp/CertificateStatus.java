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
import de.rub.nds.asn1.model.Asn1EncapsulatingBitString;
import de.rub.nds.asn1.model.Asn1EncapsulatingOctetString;
import de.rub.nds.asn1.model.Asn1EndOfContent;
import de.rub.nds.asn1.model.Asn1Explicit;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1PrimitiveGeneralizedTime;
import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.tlsattacker.core.util.Asn1ToolInitializer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.math.BigInteger;

public class CertificateStatus {

    private final Logger LOGGER = LogManager.getLogger();
    private Asn1Sequence certificateStatusSequence;
    private String hashAlgorithmIdentifier;
    private byte[] issuerNameHash;
    private byte[] issuerKeyHash;
    private BigInteger serialNumber;
    private int certificateStatus;
    private String timeOfRevocation;
    private String timeOfLastUpdate;
    private String timeOfNextUpdate;

    public CertificateStatus(Asn1Sequence certificateStatusSequence) {
        // Init ASN.1 Tool
        Asn1ToolInitializer.initAsn1Tool();

        this.certificateStatusSequence = certificateStatusSequence;
        parseCertificateStatus(certificateStatusSequence);
    }

    private void parseCertificateStatus(Asn1Sequence certStatusSeq) {
        Asn1Sequence requestInformation = (Asn1Sequence) certStatusSeq.getChildren().get(0);

        /*
         * At first, get information about the processed request. This MAY
         * differ from the original request sometimes, as some responders don't
         * need all values to match to give a response for a given certificate.
         * DigiCert's OCSP responder, for example, also accepts an invalid
         * issuerKeyHash in a request if the other values match up and returns
         * the correct one in the response.
         */

        Asn1Sequence hashAlgorithmSequence = (Asn1Sequence) requestInformation.getChildren().get(0);
        hashAlgorithmIdentifier = ((Asn1ObjectIdentifier) hashAlgorithmSequence.getChildren().get(0)).getValue();

        // Workaround for ASN.1 Tool messing up the correct type occasionally,
        // switching between Primitive and Encapsulated
        Asn1Encodable issuerNameHashObject = requestInformation.getChildren().get(1);
        Asn1Encodable issuerKeyHashObject = requestInformation.getChildren().get(2);
        if (issuerNameHashObject instanceof Asn1PrimitiveOctetString) {
            issuerNameHash = ((Asn1PrimitiveOctetString) issuerNameHashObject).getValue();
        } else if (issuerNameHashObject instanceof Asn1EncapsulatingOctetString) {
            issuerNameHash = ((Asn1EncapsulatingOctetString) issuerNameHashObject).getContent().getOriginalValue();
        }
        if (issuerKeyHashObject instanceof Asn1PrimitiveOctetString) {
            issuerKeyHash = ((Asn1PrimitiveOctetString) issuerKeyHashObject).getValue();
        } else if (issuerKeyHashObject instanceof Asn1EncapsulatingOctetString) {
            issuerKeyHash = ((Asn1EncapsulatingOctetString) issuerKeyHashObject).getContent().getOriginalValue();
        }

        // Another ASN.1 Tool bug workaround: Sometimes the serial number is
        // identified as an encapsulated bit string.
        Asn1Encodable serialNumberObject = requestInformation.getChildren().get(3);
        if (serialNumberObject instanceof Asn1Integer) {
            serialNumber = ((Asn1Integer) serialNumberObject).getValue();
        } else if (serialNumberObject instanceof Asn1EncapsulatingBitString) {
            Asn1EncapsulatingBitString serialNumberBitStringObject = (Asn1EncapsulatingBitString) serialNumberObject;
            serialNumber = new BigInteger(1, serialNumberBitStringObject.getContent().getValue());
        }

        /*
         * And here comes the revocation status. ASN.1 Tool is buggy and gets
         * sometimes Null or EndOfContent for a 'good' status, so we treat them
         * both as good status.
         */

        Asn1Encodable certStatusObject = certStatusSeq.getChildren().get(1);

        // Good status
        if (certStatusObject instanceof Asn1Null || certStatusObject instanceof Asn1EndOfContent) {
            certificateStatus = 0; // good, not revoked
        }

        // Time of next update (offset 0), revoked (offset 1) or unknown
        // (offset 2) status
        else if (certStatusObject instanceof Asn1Explicit) {
            Asn1Explicit certStatusExplicitObject = (Asn1Explicit) certStatusObject;
            switch (certStatusExplicitObject.getOffset()) {
                case 1:
                    certificateStatus = 1; // revoked
                    timeOfRevocation = ((Asn1PrimitiveGeneralizedTime) certStatusExplicitObject.getChildren().get(0))
                            .getValue();
                    break;
                case 2:
                    certificateStatus = 2; // unknown
                    break;
            }
        }

        // After the status comes the mandatory timeOfLastUpdate
        Asn1PrimitiveGeneralizedTime timeOfLastUpdateObject = (Asn1PrimitiveGeneralizedTime) certStatusSeq
                .getChildren().get(2);
        timeOfLastUpdate = timeOfLastUpdateObject.getValue();

        // And at last, optional tags for lastUpdate and extensions
        for (int i = 3; i < certStatusSeq.getChildren().size(); i++) {
            Asn1Encodable nextObject = certStatusSeq.getChildren().get(i);
            if (nextObject instanceof Asn1Explicit) {
                Asn1Explicit nextExplicitObject = (Asn1Explicit) nextObject;

                switch (nextExplicitObject.getOffset()) {
                    case 0:
                        timeOfNextUpdate = ((Asn1PrimitiveGeneralizedTime) nextExplicitObject.getChildren().get(0))
                                .getValue();
                        break;
                    case 1:
                        // TODO: Add support for singleExtensions here.
                        break;
                }
            }
        }
    }

    public Asn1Sequence getCertificateStatusSequence() {
        return certificateStatusSequence;
    }

    public void setCertificateStatusSequence(Asn1Sequence certificateStatusSequence) {
        this.certificateStatusSequence = certificateStatusSequence;
    }

    public String getHashAlgorithmIdentifier() {
        return hashAlgorithmIdentifier;
    }

    public void setHashAlgorithmIdentifier(String hashAlgorithmIdentifier) {
        this.hashAlgorithmIdentifier = hashAlgorithmIdentifier;
    }

    public byte[] getIssuerNameHash() {
        return issuerNameHash;
    }

    public void setIssuerNameHash(byte[] issuerNameHash) {
        this.issuerNameHash = issuerNameHash;
    }

    public byte[] getIssuerKeyHash() {
        return issuerKeyHash;
    }

    public void setIssuerKeyHash(byte[] issuerKeyHash) {
        this.issuerKeyHash = issuerKeyHash;
    }

    public BigInteger getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
    }

    public int getCertificateStatus() {
        return certificateStatus;
    }

    public void setCertificateStatus(int certificateStatus) {
        this.certificateStatus = certificateStatus;
    }

    public String getTimeOfRevocation() {
        return timeOfRevocation;
    }

    public void setTimeOfRevocation(String timeOfRevocation) {
        this.timeOfRevocation = timeOfRevocation;
    }

    public String getTimeOfLastUpdate() {
        return timeOfLastUpdate;
    }

    public void setTimeOfLastUpdate(String timeOfLastUpdate) {
        this.timeOfLastUpdate = timeOfLastUpdate;
    }

    public String getTimeOfNextUpdate() {
        return timeOfNextUpdate;
    }

    public void setTimeOfNextUpdate(String timeOfNextUpdate) {
        this.timeOfNextUpdate = timeOfNextUpdate;
    }
}
