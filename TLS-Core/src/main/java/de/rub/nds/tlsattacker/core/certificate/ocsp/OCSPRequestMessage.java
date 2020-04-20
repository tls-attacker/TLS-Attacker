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
import de.rub.nds.asn1.encoder.Asn1Encoder;
import de.rub.nds.asn1.model.Asn1EncapsulatingOctetString;
import de.rub.nds.asn1.model.Asn1Explicit;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.asn1.model.Asn1Sequence;
import org.apache.commons.lang3.NotImplementedException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.LinkedList;
import java.util.List;

import static de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPExtensions.ACCEPTABLE_RESPONSES;
import static de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPExtensions.NONCE;

public class OCSPRequestMessage {

    private final Logger LOGGER = LogManager.getLogger();
    Asn1Sequence tbsRequestWrapper = new Asn1Sequence();
    Asn1Sequence tbsRequest = new Asn1Sequence();
    Asn1Sequence requestList = new Asn1Sequence();
    Asn1Sequence extensionSequence = new Asn1Sequence();
    Asn1Explicit extensionExplicitSequence = new Asn1Explicit();

    boolean extensionsSet = false;

    public OCSPRequestMessage() {
        Asn1Sequence request = new Asn1Sequence();
        requestList.addChild(request);
        tbsRequest.addChild(requestList);
        tbsRequestWrapper.addChild(tbsRequest);
        extensionExplicitSequence.setOffset(2);
        extensionExplicitSequence.addChild(extensionSequence);
    }

    public OCSPRequestMessage(BigInteger serialNumberValue, byte[] issuerNameHashValue, byte[] issuerKeyHashValue) {
        Asn1Sequence request = new Asn1Sequence();
        Asn1Sequence reqCert = new Asn1Sequence();
        Asn1Sequence hashAlgorithm = new Asn1Sequence();
        Asn1Null hashAlgorithmFiller = new Asn1Null();
        Asn1ObjectIdentifier hashAlgorithmId = new Asn1ObjectIdentifier();
        Asn1PrimitiveOctetString issuerNameHash = new Asn1PrimitiveOctetString();
        Asn1PrimitiveOctetString issuerKeyHash = new Asn1PrimitiveOctetString();
        Asn1Integer serialNumber = new Asn1Integer();

        serialNumber.setValue(serialNumberValue);
        issuerNameHash.setValue(issuerNameHashValue);
        issuerKeyHash.setValue(issuerKeyHashValue);
        hashAlgorithmId.setValue("1.3.14.3.2.26"); // SHA1

        hashAlgorithm.addChild(hashAlgorithmId);
        hashAlgorithm.addChild(hashAlgorithmFiller);
        reqCert.addChild(hashAlgorithm);
        reqCert.addChild(issuerNameHash);
        reqCert.addChild(issuerKeyHash);
        reqCert.addChild(serialNumber);

        request.addChild(reqCert);
        requestList.addChild(request);
        tbsRequest.addChild(requestList);
        tbsRequestWrapper.addChild(tbsRequest);
        extensionExplicitSequence.setOffset(2);
        extensionExplicitSequence.addChild(extensionSequence);
    }

    public void addToRequest(BigInteger serialNumberValue, byte[] issuerNameHashValue, byte[] issuerKeyHashValue) {
        Asn1Sequence request = new Asn1Sequence();
        Asn1Sequence reqCert = new Asn1Sequence();
        Asn1Sequence hashAlgorithm = new Asn1Sequence();
        Asn1Null hashAlgorithmFiller = new Asn1Null();
        Asn1ObjectIdentifier hashAlgorithmId = new Asn1ObjectIdentifier();
        Asn1PrimitiveOctetString issuerNameHash = new Asn1PrimitiveOctetString();
        Asn1PrimitiveOctetString issuerKeyHash = new Asn1PrimitiveOctetString();
        Asn1Integer serialNumber = new Asn1Integer();

        serialNumber.setValue(serialNumberValue);
        issuerNameHash.setValue(issuerNameHashValue);
        issuerKeyHash.setValue(issuerKeyHashValue);
        hashAlgorithmId.setValue("1.3.14.3.2.26"); // SHA1

        hashAlgorithm.addChild(hashAlgorithmId);
        hashAlgorithm.addChild(hashAlgorithmFiller);
        reqCert.addChild(hashAlgorithm);
        reqCert.addChild(issuerNameHash);
        reqCert.addChild(issuerKeyHash);
        reqCert.addChild(serialNumber);

        request.addChild(reqCert);
        requestList.addChild(request);
    }

    public byte[] getEncodedRequest() {
        List<Asn1Encodable> asn1Encodables = new LinkedList<>();
        asn1Encodables.add(tbsRequestWrapper);

        Asn1Encoder asn1Encoder = new Asn1Encoder(asn1Encodables);
        return asn1Encoder.encode();
    }

    public void addExtension(String extensionOid) {
        if (!extensionOid.equals(NONCE.getOID()) && !extensionOid.equals(ACCEPTABLE_RESPONSES.getOID())) {
            throw new NotImplementedException("This extension is not supported yet.");
        }

        Asn1Sequence innerExtensionSequence = new Asn1Sequence();
        Asn1ObjectIdentifier oid = new Asn1ObjectIdentifier();
        oid.setValue(extensionOid);
        innerExtensionSequence.addChild(oid);

        Asn1EncapsulatingOctetString encapsulatingOctetString = new Asn1EncapsulatingOctetString();

        // Nonce
        if (extensionOid.equals(NONCE.getOID())) {
            Asn1PrimitiveOctetString nonce = new Asn1PrimitiveOctetString();

            SecureRandom rand = new SecureRandom();
            BigInteger nonceValue = new BigInteger(128, rand);

            nonce.setValue(nonceValue.toByteArray());
            encapsulatingOctetString.addChild(nonce);
        }
        // Acceptable Responses
        else if (extensionOid.equals(ACCEPTABLE_RESPONSES.getOID())) {
            Asn1Sequence oidSequence = new Asn1Sequence();
            Asn1ObjectIdentifier acceptedResponseOid = new Asn1ObjectIdentifier();
            // OCSP Basic Response
            acceptedResponseOid.setValue("1.3.6.1.5.5.7.48.1.1");
            oidSequence.addChild(acceptedResponseOid);
            encapsulatingOctetString.addChild(oidSequence);
        }

        innerExtensionSequence.addChild(encapsulatingOctetString);
        extensionSequence.addChild(innerExtensionSequence);

        if (!extensionsSet) {
            tbsRequest.addChild(extensionExplicitSequence);
            extensionsSet = true;
        }
    }
}
