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
import de.rub.nds.asn1.model.Asn1Enumerated;
import de.rub.nds.asn1.model.Asn1Explicit;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1PrimitiveGeneralizedTime;
import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.Asn1Parser;
import de.rub.nds.asn1.parser.ParserException;
import de.rub.nds.asn1.translator.ParseOcspTypesContext;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.util.Asn1ToolInitializer;
import org.apache.commons.lang3.NotImplementedException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.tls.Certificate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

public class OCSPResponseParser {

    private final Logger LOGGER = LogManager.getLogger();

    public OCSPResponseParser() {
        // Init ASN.1 Tool
        Asn1ToolInitializer.initAsn1Tool();
    }

    public OCSPResponseMessage parseResponse(byte[] encodedResponse) throws ParserException, IOException {
        OCSPResponseMessage responseMessage = new OCSPResponseMessage();
        responseMessage.setEncodedResponse(encodedResponse);

        Asn1Parser asn1Parser = new Asn1Parser(encodedResponse, false);
        List<Asn1Encodable> decodedResponse = asn1Parser.parse(ParseOcspTypesContext.NAME);

        Asn1Sequence outerWrapper = (Asn1Sequence) decodedResponse.get(0);

        // Get response status
        Asn1Enumerated encodedResponseObject = (Asn1Enumerated) outerWrapper.getChildren().get(0);
        int responseStatus = encodedResponseObject.getValue().intValue();

        // If we don't get a valid response, abort.
        if (responseStatus != 0) {
            responseMessage.setResponseStatus(responseStatus);
            return responseMessage;
        }

        Asn1Explicit responseObject = (Asn1Explicit) outerWrapper.getChildren().get(1);
        Asn1Sequence responseObjectSequence = (Asn1Sequence) responseObject.getChildren().get(0);
        Asn1ObjectIdentifier responseTypeObject = (Asn1ObjectIdentifier) responseObjectSequence.getChildren().get(0);
        String responseTypeIdentifier = responseTypeObject.getValue();

        // We only support OCSP basic responses so far
        if (!responseTypeIdentifier.equals("1.3.6.1.5.5.7.48.1.1")) {
            throw new NotImplementedException("This response type is not supported. Identifier: "
                    + responseTypeIdentifier);
        }

        Asn1EncapsulatingOctetString basicOscpResponseWrapper = (Asn1EncapsulatingOctetString) responseObjectSequence
                .getChildren().get(1);
        Asn1Sequence basicOcspResponse = (Asn1Sequence) basicOscpResponseWrapper.getChildren().get(0);

        Asn1Sequence tbsResponseData = (Asn1Sequence) basicOcspResponse.getChildren().get(0);
        Asn1Sequence signatureAlgorithmSequence = (Asn1Sequence) basicOcspResponse.getChildren().get(1);

        // Decode tbsResponseData
        Asn1Sequence responseCertificateListSequence = null;

        List<Asn1Encodable> responderDn = null;
        byte[] responderKey = null;
        int responseDataVersion = 0; // Assume it's v1 by default
        String responseTime = null;

        /*
         * Case 1 can occur twice: The first time, it can be a responder ID,
         * namely providing the distinguished name. After the response list,
         * it's for extensions. However, extensions always come after the
         * response list. Therefore, if we passed the response, treat this case
         * for extensions.
         */

        for (Asn1Encodable enc : tbsResponseData.getChildren()) {
            if (enc instanceof Asn1Explicit) {
                Asn1Explicit currentObject = (Asn1Explicit) enc;
                Asn1Encodable childObject = ((Asn1Explicit) enc).getChildren().get(0);
                switch (currentObject.getOffset()) {
                    case 0:
                        responseDataVersion = ((Asn1Integer) childObject).getValue().intValue();
                        break;
                    case 1:
                        if (responseCertificateListSequence == null) {
                            responderDn = ((Asn1Sequence) childObject).getChildren();
                        } else {
                            // TODO: Add support for responseExtensions here.
                        }
                        break;
                    case 2:
                        responderKey = ((Asn1PrimitiveOctetString) childObject).getValue();
                        break;
                }
            } else if (enc instanceof Asn1PrimitiveGeneralizedTime) {
                responseTime = ((Asn1PrimitiveGeneralizedTime) enc).getValue();
            } else if (enc instanceof Asn1Sequence) {
                responseCertificateListSequence = (Asn1Sequence) enc;
            }
        }

        // Decode every listed certificate status from tbsResponseData
        List<CertificateStatus> certificateStatusList = new LinkedList<>();
        if (responseCertificateListSequence != null) {
            for (Asn1Encodable certificateStatusSequence : responseCertificateListSequence.getChildren()) {
                if (certificateStatusSequence instanceof Asn1Sequence) {
                    certificateStatusList.add(new CertificateStatus((Asn1Sequence) certificateStatusSequence));
                }
            }
        }

        // Signature of the OCSP Response can either be a primitive or an
        // encapsulated type, so let's deal with that later in the getter
        String signatureAlgorithmIdentifier = ((Asn1ObjectIdentifier) signatureAlgorithmSequence.getChildren().get(0))
                .getValue();
        Asn1Encodable signature = basicOcspResponse.getChildren().get(2);

        Asn1Explicit certs = null;
        if (basicOcspResponse.getChildren().size() > 3) {
            certs = (Asn1Explicit) basicOcspResponse.getChildren().get(3);
        }

        // And if a certificate was embedded, parse it with BouncyCastle.
        Certificate certificate = null;
        if (certs != null) {
            // Grab the certificate Asn1Sequence
            Asn1Sequence certOuterSequence = (Asn1Sequence) certs.getChildren().get(0);
            Asn1Sequence certSequence = (Asn1Sequence) certOuterSequence.getChildren().get(0);

            // Re-encode it to DER, as if we would get a normal DER encoded
            // certificate
            List<Asn1Encodable> toEncode = new LinkedList<>();
            toEncode.add(certSequence);
            Asn1Encoder asn1Encoder = new Asn1Encoder(toEncode);

            // Mimic TLS certificate message format with two length values in
            // front of the certificate data
            byte[] certificateSequenceEncoded = asn1Encoder.encode();
            byte[] certificateSequenceEncodedWithLength = ArrayConverter.concatenate(ArrayConverter.intToBytes(
                    certificateSequenceEncoded.length, HandshakeByteLength.CERTIFICATES_LENGTH),
                    certificateSequenceEncoded);
            ByteArrayInputStream stream = new ByteArrayInputStream(ArrayConverter.concatenate(ArrayConverter
                    .intToBytes(certificateSequenceEncodedWithLength.length, HandshakeByteLength.CERTIFICATES_LENGTH),
                    certificateSequenceEncodedWithLength));

            // And feed the TLS mimicked certificate message into BouncyCastle
            // TLS certificate parser
            certificate = Certificate.parse(stream);
        }

        // If we're done with parsing, fill the OCSP response message
        responseMessage.setCertificateStatusList(certificateStatusList);
        if (responderKey != null) {
            responseMessage.setResponderKey(responderKey);
        }
        responseMessage.setResponseDataVersion(responseDataVersion);
        if (responseTime != null) {
            responseMessage.setResponseTime(responseTime);
        }
        responseMessage.setResponseTypeIdentifier(responseTypeIdentifier);
        responseMessage.setSignatureAlgorithmIdentifier(signatureAlgorithmIdentifier);
        responseMessage.setSignature(signature);
        if (responderDn != null) {
            responseMessage.setResponderDn(responderDn);
        }
        if (certificate != null) {
            responseMessage.setCertificate(certificate);
        }

        return responseMessage;
    }
}
