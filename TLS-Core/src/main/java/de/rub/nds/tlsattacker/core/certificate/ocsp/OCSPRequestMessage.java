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

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.LinkedList;
import java.util.List;

import static de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPResponseTypes.*;

public class OCSPRequestMessage {

    Asn1Sequence tbsRequestWrapper = new Asn1Sequence();
    Asn1Sequence tbsRequest = new Asn1Sequence();
    Asn1Sequence requestList = new Asn1Sequence();
    Asn1Sequence extensionSequence = new Asn1Sequence();
    Asn1Explicit extensionExplicitSequence = new Asn1Explicit();
    BigInteger nonce;

    boolean extensionsSet = false;

    public OCSPRequestMessage() {
        tbsRequest.addChild(requestList);
        tbsRequestWrapper.addChild(tbsRequest);
        extensionExplicitSequence.setOffset(2);
        extensionExplicitSequence.addChild(extensionSequence);
    }

    public OCSPRequestMessage(byte[] issuerNameHashValue, byte[] issuerKeyHashValue, BigInteger serialNumberValue) {
        addToRequest(issuerNameHashValue, issuerKeyHashValue, serialNumberValue);
        tbsRequest.addChild(requestList);
        tbsRequestWrapper.addChild(tbsRequest);
        extensionExplicitSequence.setOffset(2);
        extensionExplicitSequence.addChild(extensionSequence);
    }

    public Asn1Sequence getTbsRequestWrapper() {
        return tbsRequestWrapper;
    }

    public void setTbsRequestWrapper(Asn1Sequence tbsRequestWrapper) {
        this.tbsRequestWrapper = tbsRequestWrapper;
    }

    public Asn1Sequence getTbsRequest() {
        return tbsRequest;
    }

    public void setTbsRequest(Asn1Sequence tbsRequest) {
        this.tbsRequest = tbsRequest;
    }

    public Asn1Sequence getRequestList() {
        return requestList;
    }

    public void setRequestList(Asn1Sequence requestList) {
        this.requestList = requestList;
    }

    public Asn1Sequence getExtensionSequence() {
        return extensionSequence;
    }

    public void setExtensionSequence(Asn1Sequence extensionSequence) {
        this.extensionSequence = extensionSequence;
    }

    public Asn1Explicit getExtensionExplicitSequence() {
        return extensionExplicitSequence;
    }

    public void setExtensionExplicitSequence(Asn1Explicit extensionExplicitSequence) {
        this.extensionExplicitSequence = extensionExplicitSequence;
    }

    public boolean isExtensionsSet() {
        return extensionsSet;
    }

    public void setExtensionsSet(boolean extensionsSet) {
        this.extensionsSet = extensionsSet;
    }

    public BigInteger getNonce() {
        return nonce;
    }

    public void setNonce(BigInteger nonce) {
        this.nonce = nonce;
    }

    public void addToRequest(byte[] issuerNameHashValue, byte[] issuerKeyHashValue, BigInteger serialNumberValue) {
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
            Asn1PrimitiveOctetString nonceOctetString = new Asn1PrimitiveOctetString();

            SecureRandom rand = new SecureRandom();
            if (nonce == null) {
                nonce = new BigInteger(128, rand);
            }

            nonceOctetString.setValue(nonce.toByteArray());
            encapsulatingOctetString.addChild(nonceOctetString);
        }
        // Acceptable Responses
        else if (extensionOid.equals(ACCEPTABLE_RESPONSES.getOID())) {
            Asn1Sequence oidSequence = new Asn1Sequence();
            Asn1ObjectIdentifier acceptedResponseOid = new Asn1ObjectIdentifier();
            // OCSP Basic Response
            acceptedResponseOid.setValue(BASIC.getOID());
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
