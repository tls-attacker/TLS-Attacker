/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate.transparency;

import de.rub.nds.tlsattacker.core.constants.CertificateTransparencyLength;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SignedCertificateTimestampParser extends Parser<SignedCertificateTimestamp> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser
     *
     * @param stream
     */
    public SignedCertificateTimestampParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(SignedCertificateTimestamp signedCertificateTimestamp) {
        // Decode and parse SCT version
        SignedCertificateTimestampVersion sctVersion =
                SignedCertificateTimestampVersion.decodeVersion(parseByteField(1));
        signedCertificateTimestamp.setVersion(sctVersion);

        // Decode 32 byte log id
        signedCertificateTimestamp.setLogId(
                parseByteArrayField(CertificateTransparencyLength.LOG_ID));

        // Decode 8 byte unix timestamp
        byte[] sctTimestamp = parseByteArrayField(CertificateTransparencyLength.TIMESTAMP);
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.put(sctTimestamp, 0, sctTimestamp.length);
        buffer.flip(); // need flip

        long decodedTimestamp = buffer.getLong();
        signedCertificateTimestamp.setTimestamp(decodedTimestamp);

        // Decode extension length for variable-length encoded extensions
        int extensionLength = parseIntField(CertificateTransparencyLength.EXTENSION_LENGTH);

        // Currently there are no extensions defined for
        // SignedCertificateTimestamps. We do not further parse or handle
        // extensions contained in a SignedCertificateTimestamp. Instead, we
        // just copy the plain byte values.
        if (extensionLength == 0) {
            signedCertificateTimestamp.setExtensions(new byte[0]);
        } else {
            byte[] encodedExtension = parseByteArrayField(extensionLength);
            signedCertificateTimestamp.setExtensions(encodedExtension);
        }

        // Decode signature (currently only copied and not further parsed)
        byte[] encodedSignature = parseByteArrayField(getBytesLeft());
        SignedCertificateTimestampSignatureParser signatureParser =
                new SignedCertificateTimestampSignatureParser(
                        new ByteArrayInputStream(encodedSignature));
        SignedCertificateTimestampSignature signature = new SignedCertificateTimestampSignature();
        signatureParser.parse(signature);
        signedCertificateTimestamp.setSignature(signature);

        signedCertificateTimestamp.setEncodedTimestamp(getAlreadyParsed());
    }
}
