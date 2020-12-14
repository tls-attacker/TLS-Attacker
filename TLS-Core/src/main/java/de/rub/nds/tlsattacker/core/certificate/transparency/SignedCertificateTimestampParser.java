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
import de.rub.nds.tlsattacker.core.protocol.parser.Parser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.ByteBuffer;

public class SignedCertificateTimestampParser extends Parser<SignedCertificateTimestamp> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser
     *
     * @param startposition
     *            Position in the array from which the Parser should start
     *            working
     * @param array
     */
    public SignedCertificateTimestampParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public SignedCertificateTimestamp parse() {
        try {
            // Create SCT object & save encoded response in it
            SignedCertificateTimestamp certificateTimestamp = new SignedCertificateTimestamp();
            // certificateTimestamp.setEncodedTimestamp(encodedTimestamp);

            // Decode and parse SCT version
            SignedCertificateTimestampVersion sctVersion = SignedCertificateTimestampVersion
                    .decodeVersion(parseByteField(1));
            certificateTimestamp.setVersion(sctVersion);

            // Decode 32 byte log id
            certificateTimestamp.setLogId(parseByteArrayField(32));

            // Decode 8 byte unix timestamp
            byte[] sctTimestamp = parseByteArrayField(8);
            ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
            buffer.put(sctTimestamp, 0, sctTimestamp.length);
            buffer.flip(); // need flip

            long decodedTimestamp = buffer.getLong();
            certificateTimestamp.setTimestamp(decodedTimestamp);

            // Decode extension length for variable-length encoded extensions
            int extensionLength = parseIntField(2);

            // Currently there are no extensions defined for
            // SignedCertificateTimestamps. We do not further parse or handle
            // extensions contained in a SignedCertificateTimestamp. Instead, we
            // just copy the plain byte values.
            if (extensionLength == 0) {
                certificateTimestamp.setExtensions(new byte[0]);
            } else {
                byte[] encodedExtension = parseByteArrayField(extensionLength);
                certificateTimestamp.setExtensions(encodedExtension);
            }

            // Decode signature (currently only copied and not further parsed)
            byte[] encodedSignature = parseByteArrayField(getBytesLeft());
            SignedCertificateTimestampSignatureParser signatureParser = new SignedCertificateTimestampSignatureParser(
                    0, encodedSignature);
            SignedCertificateTimestampSignature signature = signatureParser.parse();
            certificateTimestamp.setSignature(signature);

            return certificateTimestamp;
        } catch (ParserException e) {
            LOGGER.warn("Could not parse CertificateTimestamp", e);
        }

        return null;
    }
}
