/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.certificate.ocsp;

import static de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPResponseTypes.ACCEPTABLE_RESPONSES;
import static de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPResponseTypes.BASIC;
import static de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPResponseTypes.NONCE;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.encoder.Asn1Encoder;
import de.rub.nds.asn1.model.Asn1EncapsulatingOctetString;
import de.rub.nds.asn1.model.Asn1Explicit;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.tlsattacker.core.certificate.ObjectIdentifierTranslator;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import org.apache.commons.lang3.NotImplementedException;

public class OCSPRequestMessage {

    Asn1Sequence tbsRequestWrapper = new Asn1Sequence();
    Asn1Sequence tbsRequest = new Asn1Sequence();
    Asn1Sequence requestList = new Asn1Sequence();
    Asn1Sequence extensionSequence = new Asn1Sequence();
    Asn1Explicit extensionExplicitSequence = new Asn1Explicit();
    BigInteger nonce;

    // see RFC 6960: TBSRequest -> [2] requestExtensions
    private static final int EXTENSION_ASN1_EXPLICIT_OFFSET = 2;
    private static final int NONCE_RANDOM_SEED = 42;
    private static final int NONCE_LENGTH_BIT = 128;

    boolean extensionsSet = false;

    public OCSPRequestMessage() {
        tbsRequest.addChild(requestList);
        tbsRequestWrapper.addChild(tbsRequest);
        extensionExplicitSequence.setOffset(EXTENSION_ASN1_EXPLICIT_OFFSET);
        extensionExplicitSequence.addChild(extensionSequence);
    }

    public OCSPRequestMessage(byte[] issuerNameHashValue, byte[] issuerKeyHashValue, BigInteger serialNumberValue) {
        addToRequest(issuerNameHashValue, issuerKeyHashValue, serialNumberValue);
        tbsRequest.addChild(requestList);
        tbsRequestWrapper.addChild(tbsRequest);
        extensionExplicitSequence.setOffset(EXTENSION_ASN1_EXPLICIT_OFFSET);
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
        Asn1Null hashAlgorithmFiller = new Asn1Null();
        Asn1ObjectIdentifier hashAlgorithmId = new Asn1ObjectIdentifier();
        Asn1PrimitiveOctetString issuerNameHash = new Asn1PrimitiveOctetString();
        Asn1PrimitiveOctetString issuerKeyHash = new Asn1PrimitiveOctetString();
        Asn1Integer serialNumber = new Asn1Integer();

        serialNumber.setValue(serialNumberValue);
        issuerNameHash.setValue(issuerNameHashValue);
        issuerKeyHash.setValue(issuerKeyHashValue);
        hashAlgorithmId.setValue(ObjectIdentifierTranslator.translate("SHA1"));
        Asn1Sequence request = new Asn1Sequence();
        Asn1Sequence reqCert = new Asn1Sequence();
        Asn1Sequence hashAlgorithm = new Asn1Sequence();

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

            Random rand = new Random(NONCE_RANDOM_SEED);
            if (nonce == null) {
                nonce = new BigInteger(NONCE_LENGTH_BIT, rand);
            }

            nonceOctetString.setValue(nonce.toByteArray());
            encapsulatingOctetString.addChild(nonceOctetString);
        } else if (extensionOid.equals(ACCEPTABLE_RESPONSES.getOID())) {
            // Acceptable Responses
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
