/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import static de.rub.nds.modifiablevariable.util.ArrayConverter.bytesToHexString;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignedCertificateTimestampExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SignedCertificateTimestampExtensionParser extends
        ExtensionParser<SignedCertificateTimestampExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SignedCertificateTimestampExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    /**
     * Parses the content of the SingedCertificateTimestampExtension
     *
     * @param msg
     *            The Message that should be parsed into
     */
    @Override
    public void parseExtensionMessageContent(SignedCertificateTimestampExtensionMessage msg) {
        if (msg.getExtensionLength().getValue() > 65535) {
            LOGGER.warn("The SingedCertificateTimestamp ticket length shouldn't exceed 2 bytes as defined in RFC 6962. "
                    + "Length was " + msg.getExtensionLength().getValue());
        }
        msg.setSignedTimestamp(parseByteArrayField(msg.getExtensionLength().getValue()));
        LOGGER.debug("The signed certificate timestamp extension parser parsed the value "
                + bytesToHexString(msg.getSignedTimestamp()));
    }

    /**
     * Creates a new SignedCertificateTimestampExtensionMessage
     *
     * @return A new SignedCertificateTimestampExtensionMessage
     */
    @Override
    protected SignedCertificateTimestampExtensionMessage createExtensionMessage() {
        return new SignedCertificateTimestampExtensionMessage();
    }

}
