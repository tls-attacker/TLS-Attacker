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
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.asn1.model.Asn1Sequence;

import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;

public class OCSPRequestMessage {

    Asn1Sequence tbsRequestWrapper = new Asn1Sequence();
    Asn1Sequence tbsRequest = new Asn1Sequence();
    Asn1Sequence requestList = new Asn1Sequence();

    public OCSPRequestMessage() {
        Asn1Sequence request = new Asn1Sequence();
        requestList.addChild(request);
        tbsRequest.addChild(requestList);
        tbsRequestWrapper.addChild(tbsRequest);
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
}
