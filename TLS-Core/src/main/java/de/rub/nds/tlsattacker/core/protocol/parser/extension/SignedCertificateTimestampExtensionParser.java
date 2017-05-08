/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.SignedCertificateTimestampExtensionMessage;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class SignedCertificateTimestampExtensionParser extends
        ExtensionParser<SignedCertificateTimestampExtensionMessage> {

    /**
     * Constructor
     * 
     * @param startposition
     * @param array
     */
    public SignedCertificateTimestampExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    /**
     * Parses the content of the SingedCertificateTimestampExtension
     * 
     * @param msg
     */
    @Override
    public void parseExtensionMessageContent(SignedCertificateTimestampExtensionMessage msg) {
        if (msg.getExtensionLength().getValue() > 65535) {
            LOGGER.warn("The SingedCertificateTimestamp ticket length shouldn't exceed 2 bytes as defined in RFC 6962. "
                    + "Length was " + msg.getExtensionLength().getValue());
        }
        msg.setSignedTimestamp(parseByteArrayField(msg.getExtensionLength().getValue()));
    }

    /**
     * Creates a new SignedCertificateTimestampExtensionMessage
     * 
     * @return
     */
    @Override
    protected SignedCertificateTimestampExtensionMessage createExtensionMessage() {
        return new SignedCertificateTimestampExtensionMessage();
    }

}
