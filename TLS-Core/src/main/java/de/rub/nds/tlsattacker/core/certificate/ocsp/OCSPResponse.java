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
import de.rub.nds.asn1.parser.contentunpackers.ContentUnpackerRegister;
import de.rub.nds.asn1.parser.contentunpackers.DefaultContentUnpacker;
import de.rub.nds.asn1.parser.contentunpackers.PrimitiveBitStringUnpacker;
import de.rub.nds.asn1.translator.ContextRegister;
import de.rub.nds.asn1.translator.ParseNativeTypesContext;
import de.rub.nds.asn1.translator.ParseOcspTypesContext;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.tls.Certificate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

// TODO: Find a way to share this variable
import static de.rub.nds.tlsattacker.core.certificate.ocsp.CertificateInformationExtractor.asn1ToolInitialized;

public class OCSPResponse {

    private final Logger LOGGER = LogManager.getLogger();
    private final List<CertificateStatus> certStatusList = new LinkedList<>();
    private byte[] encodedResponse;
    private byte[] responderKey;
    private int responseStatus;
    private int responseDataVersion = 0; // 0 = OCSP v1
    private String responseTime;
    private String responseTypeIdentifier;
    private String signatureAlgorithmIdentifier;
    private Asn1Encodable signature;
    private List<Asn1Encodable> responderDn;
    private Certificate cert;

    public OCSPResponse() {
        // Init ASN.1 Tool
        if (!asn1ToolInitialized) {
            registerContexts();
            registerContentUnpackers();
            asn1ToolInitialized = true;
        }
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

    public void parseResponse(byte[] encodedResponse) throws ParserException, IOException {
        this.encodedResponse = encodedResponse;

        Asn1Parser asn1Parser = new Asn1Parser(encodedResponse, false);
        List<Asn1Encodable> asn1Encodables = asn1Parser.parse(ParseOcspTypesContext.NAME);

        Asn1Sequence outerWrapper = (Asn1Sequence) asn1Encodables.get(0);

        // Get response status
        Asn1Enumerated encodedResponseObject = (Asn1Enumerated) outerWrapper.getChildren().get(0);
        responseStatus = encodedResponseObject.getValue().intValue();

        // If we don't get a valid response, abort.
        if (responseStatus != 0) {
            return;
        }

        Asn1Explicit responseObject = (Asn1Explicit) outerWrapper.getChildren().get(1);
        Asn1Sequence responseObjectSequence = (Asn1Sequence) responseObject.getChildren().get(0);
        Asn1ObjectIdentifier responseTypeObject = (Asn1ObjectIdentifier) responseObjectSequence.getChildren().get(0);
        responseTypeIdentifier = responseTypeObject.getValue();

        // We only support OCSP basic responses so far
        if (!responseTypeIdentifier.equals("1.3.6.1.5.5.7.48.1.1")) {
            return;
        }

        Asn1EncapsulatingOctetString basicOscpResponseWrapper = (Asn1EncapsulatingOctetString) responseObjectSequence
                .getChildren().get(1);
        Asn1Sequence basicOcspResponse = (Asn1Sequence) basicOscpResponseWrapper.getChildren().get(0);

        Asn1Sequence tbsResponseData = (Asn1Sequence) basicOcspResponse.getChildren().get(0);
        Asn1Sequence signatureAlgorithmSequence = (Asn1Sequence) basicOcspResponse.getChildren().get(1);

        // Decode tbsResponseData
        Asn1Sequence responseCertListSequence = null;

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
                        if (responseCertListSequence == null) {
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
                responseCertListSequence = (Asn1Sequence) enc;
            }
        }

        // Decode every listed certificate status from tbsResponseData
        if (responseCertListSequence != null) {
            for (Asn1Encodable certStatusSequence : responseCertListSequence.getChildren()) {
                if (certStatusSequence instanceof Asn1Sequence) {
                    certStatusList.add(new CertificateStatus((Asn1Sequence) certStatusSequence));
                }
            }
        }

        // Signature of the OCSP Response can either be a primitive or an
        // encapsulated type, so let's deal with that later in the getter
        signatureAlgorithmIdentifier = ((Asn1ObjectIdentifier) signatureAlgorithmSequence.getChildren().get(0))
                .getValue();
        signature = basicOcspResponse.getChildren().get(2);

        Asn1Explicit certs = null;
        if (basicOcspResponse.getChildren().size() > 3) {
            certs = (Asn1Explicit) basicOcspResponse.getChildren().get(3);
        }

        // And if a certificate was embedded, parse it with BouncyCastle.
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
            byte[] certSequenceEncoded = asn1Encoder.encode();
            byte[] certSequenceEncodedWithLength = ArrayConverter.concatenate(
                    ArrayConverter.intToBytes(certSequenceEncoded.length, HandshakeByteLength.CERTIFICATES_LENGTH),
                    certSequenceEncoded);
            ByteArrayInputStream stream = new ByteArrayInputStream(ArrayConverter.concatenate(ArrayConverter
                    .intToBytes(certSequenceEncodedWithLength.length, HandshakeByteLength.CERTIFICATES_LENGTH),
                    certSequenceEncodedWithLength));

            // And feed the TLS mimicked certificate message into BouncyCastle
            // TLS certificate parser
            cert = Certificate.parse(stream);
        }
    }
}
