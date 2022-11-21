/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.certificate.ocsp;

import static de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPResponseTypes.BASIC;
import static de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPResponseTypes.NONCE;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.encoder.Asn1Encoder;
import de.rub.nds.asn1.model.Asn1EncapsulatingBitString;
import de.rub.nds.asn1.model.Asn1EncapsulatingOctetString;
import de.rub.nds.asn1.model.Asn1Enumerated;
import de.rub.nds.asn1.model.Asn1Explicit;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.asn1.model.Asn1PrimitiveGeneralizedTime;
import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.Asn1Parser;
import de.rub.nds.asn1.parser.ParserException;
import de.rub.nds.asn1.translator.ParseOcspTypesContext;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.util.Asn1ToolInitializer;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.apache.commons.lang3.NotImplementedException;
import org.bouncycastle.crypto.tls.Certificate;

public class OCSPResponseParser {

    public static OCSPResponse parseResponse(byte[] encodedResponse) throws ParserException, IOException {
        // Initialize ASN.1 Tool
        Asn1ToolInitializer.initAsn1Tool();

        // Create OCSPResponse object & save encoded response in it
        OCSPResponse responseMessage = new OCSPResponse();
        responseMessage.setEncodedResponse(encodedResponse);

        // Start parsing the response
        Asn1Parser asn1Parser = new Asn1Parser(encodedResponse, false);
        List<Asn1Encodable> decodedResponse = asn1Parser.parse(ParseOcspTypesContext.NAME);

        // Unpack response, which is wrapped in one big SEQUENCE
        Asn1Sequence outerSequence = (Asn1Sequence) decodedResponse.get(0);

        // Get response status
        Asn1Enumerated responseStatusObject = (Asn1Enumerated) outerSequence.getChildren().get(0);
        int responseStatus = responseStatusObject.getValue().intValue();

        // If we don't get a valid response, abort.
        if (responseStatus != 0) {
            return null;
        }

        // Unpack responseBytes & check if it's an OCSP basic response.
        Asn1Explicit responseBytesObject = (Asn1Explicit) outerSequence.getChildren().get(1);
        Asn1Sequence responseBytesSequence = (Asn1Sequence) responseBytesObject.getChildren().get(0);
        Asn1ObjectIdentifier responseTypeObject = (Asn1ObjectIdentifier) responseBytesSequence.getChildren().get(0);
        String responseTypeIdentifier = responseTypeObject.getValue();

        // Save status & response type to OCSPResponse object
        responseMessage.setResponseStatus(responseStatus);
        responseMessage.setResponseTypeIdentifier(responseTypeIdentifier);

        // Abort if not an OCSP basic response.
        if (!responseTypeIdentifier.equals(BASIC.getOID())) {
            throw new NotImplementedException(
                "This response type is not supported. Identifier: " + responseTypeIdentifier);
        }

        // Parse OCSP basic response object. See RFC 6960 for reference of
        // structure.
        parseBasicResponse(responseBytesSequence, responseMessage);

        return responseMessage;
    }

    private static void parseBasicResponse(Asn1Sequence basicResponseSequence, OCSPResponse responseMessage)
        throws IOException {
        // Unpack OCSP basic response, which is wrapped in an encapsulating
        // octet string
        Asn1EncapsulatingOctetString basicOSCPResponseEncapsulated =
            (Asn1EncapsulatingOctetString) basicResponseSequence.getChildren().get(1);
        Asn1Sequence basicOcspResponse = (Asn1Sequence) basicOSCPResponseEncapsulated.getChildren().get(0);

        // Unpack tbsResponse
        Asn1Sequence tbsResponseData = (Asn1Sequence) basicOcspResponse.getChildren().get(0);

        // Decode tbsResponseData
        List<Asn1Encodable> responderName = null;
        byte[] responderKey = null;
        Integer responseDataVersion = null;
        String producedAt = null;
        Asn1Sequence certificateStatusSequence = null;

        // Parse data in ResponseData & ResponderID. For reference, see ASN.1
        // Syntax in RFC 6960.

        /*
         * Asn1Explicit Offset 0: Version Asn1Explicit Offset 1: Either responderName, or at the end of the
         * responseData: responseExtensions Asn1Explicit Offset 2: responderHash Asn1PrimitiveGeneralizedTime:
         * producedAt Asn1Sequence: responses, which contain statuses for each requested certificate
         */

        for (Asn1Encodable responseDataObject : tbsResponseData.getChildren()) {
            if (responseDataObject instanceof Asn1Explicit) {
                Asn1Explicit currentObject = (Asn1Explicit) responseDataObject;
                Asn1Encodable childObject = ((Asn1Explicit) responseDataObject).getChildren().get(0);
                switch (currentObject.getOffset()) {
                    case 0:
                        responseDataVersion = ((Asn1Integer) childObject).getValue().intValue();
                        break;
                    case 1:
                        // If we haven't passed the certificate status sequence,
                        // it's the responderName.
                        if (certificateStatusSequence == null) {
                            responderName = ((Asn1Sequence) childObject).getChildren();
                        } else {
                            // But if we passed the sequence, it's
                            // responseExtensions
                            parseBasicResponseExtensions((Asn1Sequence) childObject, responseMessage);
                        }
                        break;
                    default:
                        // Workaround for yet another ASN.1 Tool mismatch
                        if (childObject instanceof Asn1PrimitiveOctetString) {
                            responderKey = ((Asn1PrimitiveOctetString) childObject).getValue();
                        } else if (childObject instanceof Asn1EncapsulatingOctetString) {
                            responderKey = ((Asn1EncapsulatingOctetString) childObject).getContent().getValue();
                        }
                        break;
                }
            } else if (responseDataObject instanceof Asn1PrimitiveGeneralizedTime) {
                producedAt = ((Asn1PrimitiveGeneralizedTime) responseDataObject).getValue();
            } else if (responseDataObject instanceof Asn1Sequence) {
                certificateStatusSequence = (Asn1Sequence) responseDataObject;
            }
        }

        // Unpack 'response' sequence, and parse each one as one Certificate
        // Status
        List<CertificateStatus> certificateStatusList = new LinkedList<>();
        if (certificateStatusSequence != null) {
            for (Asn1Encodable singleCertificateStatusSequence : certificateStatusSequence.getChildren()) {
                if (singleCertificateStatusSequence instanceof Asn1Sequence) {
                    // Create a new Certificate Status object for each entry
                    certificateStatusList.add(
                        CertificateStatusParser.parseCertificateStatus((Asn1Sequence) singleCertificateStatusSequence));
                }
            }
        }

        // If we're done with parsing, fill the OCSP response message
        responseMessage.setResponseDataVersion(responseDataVersion);
        if (responderKey != null) {
            responseMessage.setResponderKey(responderKey);
        }
        if (responderName != null) {
            responseMessage.setResponderName(responderName);
        }
        if (producedAt != null) {
            responseMessage.setProducedAt(producedAt);
        }
        responseMessage.setCertificateStatusList(certificateStatusList);

        // And continue with parsing the signature
        parseBasicResponseSignature(basicOcspResponse, responseMessage);
    }

    private static void parseBasicResponseSignature(Asn1Sequence basicOcspResponse, OCSPResponse responseMessage)
        throws IOException {
        // Unpack signature algorithm
        Asn1Sequence signatureAlgorithmSequence = (Asn1Sequence) basicOcspResponse.getChildren().get(1);
        String signatureAlgorithmIdentifier =
            ((Asn1ObjectIdentifier) signatureAlgorithmSequence.getChildren().get(0)).getValue();

        // Parse signature
        byte[] signature = null;
        Asn1Encodable signatureObject = basicOcspResponse.getChildren().get(2);

        // Signature can either be a primitive or an encapsulated one
        if (signatureObject instanceof Asn1PrimitiveBitString) {
            Asn1PrimitiveBitString signatureBitString = (Asn1PrimitiveBitString) signatureObject;
            signature = signatureBitString.getValue();
        } else if (signatureObject instanceof Asn1EncapsulatingBitString) {
            Asn1EncapsulatingBitString signatureBitString = (Asn1EncapsulatingBitString) signatureObject;
            signature = signatureBitString.getContent().getValue();

            // Remove leading 0x00 byte
            if (signature[0] == 0x00 && (signature.length % 2) == 1) {
                signature = Arrays.copyOfRange(signature, 1, signature.length);
            }
        }

        // Unpack certificates, if response contains one. They're optional.
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
            byte[] certificateSequenceEncodedWithLength = ArrayConverter.concatenate(
                ArrayConverter.intToBytes(certificateSequenceEncoded.length, HandshakeByteLength.CERTIFICATES_LENGTH),
                certificateSequenceEncoded);
            ByteArrayInputStream stream = new ByteArrayInputStream(
                ArrayConverter.concatenate(ArrayConverter.intToBytes(certificateSequenceEncodedWithLength.length,
                    HandshakeByteLength.CERTIFICATES_LENGTH), certificateSequenceEncodedWithLength));

            // And feed the TLS mimicked certificate message into BouncyCastle
            // TLS certificate parser
            certificate = Certificate.parse(stream);
        }

        // Save signature & certificates to our OCSPResponse object
        responseMessage.setSignatureAlgorithmIdentifier(signatureAlgorithmIdentifier);
        responseMessage.setSignature(signature);
        if (certificate != null) {
            responseMessage.setCertificate(certificate);
        }
    }

    private static void parseBasicResponseExtensions(Asn1Sequence extensionSequence, OCSPResponse responseMessage) {
        Asn1Sequence innerExtensionSequence = (Asn1Sequence) extensionSequence.getChildren().get(0);
        Asn1ObjectIdentifier extensionIdentifier = (Asn1ObjectIdentifier) innerExtensionSequence.getChildren().get(0);

        // Nonce extension
        BigInteger nonce = null;
        if (extensionIdentifier.getValue().equals(NONCE.getOID())) {
            Asn1EncapsulatingOctetString encapsulatedNonce =
                (Asn1EncapsulatingOctetString) innerExtensionSequence.getChildren().get(1);
            Asn1PrimitiveOctetString nonceOctetString =
                (Asn1PrimitiveOctetString) encapsulatedNonce.getChildren().get(0);
            nonce = new BigInteger(1, nonceOctetString.getValue());
        }

        if (nonce != null) {
            responseMessage.setNonce(nonce);
        }
    }
}
