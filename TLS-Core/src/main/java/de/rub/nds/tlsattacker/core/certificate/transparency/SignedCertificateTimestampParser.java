/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.certificate.transparency;

import de.rub.nds.asn1.parser.ParserException;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class SignedCertificateTimestampParser {
    public static SignedCertificateTimestamp parseTimestamp(byte[] encodedTimestamp) throws ParserException {

        // Create SCT object & save encoded response in it
        SignedCertificateTimestamp certificateTimestamp = new SignedCertificateTimestamp();
        certificateTimestamp.setEncodedTimestamp(encodedTimestamp);

        // Use index value to navigate through fixed-length encoded SCT
        int index = 0;

        // Decode and parse SCT version
        SignedCertificateTimestampVersion sctVersion = SignedCertificateTimestampVersion
                .decodeVersion(encodedTimestamp[index]);
        certificateTimestamp.setVersion(sctVersion);
        index++;

        // Decode 32 byte log id
        byte[] sctLogId = Arrays.copyOfRange(encodedTimestamp, index, index + 32);
        certificateTimestamp.setLogId(sctLogId);
        index += 32;

        // Decode 8 byte unix timestamp
        byte[] sctTimestamp = Arrays.copyOfRange(encodedTimestamp, index, index + 8);
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.put(sctTimestamp, 0, sctTimestamp.length);
        buffer.flip(); // need flip

        long decodedTimestamp = buffer.getLong();
        certificateTimestamp.setTimestamp(decodedTimestamp);
        index += 8;

        // Decode extension length for variable-length encoded extensions
        int extensionLength = encodedTimestamp[index] << 8 | encodedTimestamp[index + 1] & 0x00ff;

        // Currently there are no extensions defined for
        // SignedCertificateTimestamps. We do not further parse or handle
        // extensions contained in a SignedCertificateTimestamp. Instead, we
        // just copy the plain byte values.
        if (extensionLength == 0) {
            certificateTimestamp.setExtensions(new byte[0]);
        } else {
            byte[] encodedExtension = Arrays.copyOfRange(encodedTimestamp, index + 2, index + 2 + extensionLength);
            certificateTimestamp.setExtensions(encodedExtension);
        }

        // Increment index by 2 byte (length field) + total variable-extension
        // length
        index += 2 + extensionLength;

        // Decode signature (currently only copied and not further parsed)
        byte[] encodedSignature = Arrays.copyOfRange(encodedTimestamp, index, encodedTimestamp.length);
        SignedCertificateTimestampSignatureParser signatureParser = new SignedCertificateTimestampSignatureParser(0,
                encodedSignature);
        SignedCertificateTimestampSignature signature = signatureParser.parse();
        certificateTimestamp.setSignature(signature);

        return certificateTimestamp;
    }
}
