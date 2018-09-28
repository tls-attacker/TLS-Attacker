/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.SignedCertificateTimestampExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SignedCertificateTimestampExtensionSerializer extends
        ExtensionSerializer<SignedCertificateTimestampExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SignedCertificateTimestampExtensionMessage message;

    /**
     * Constructor
     *
     * @param message
     *            A SignedCertificateTimestampExtensionMessage
     */
    public SignedCertificateTimestampExtensionSerializer(SignedCertificateTimestampExtensionMessage message) {
        super(message);
        this.message = message;
    }

    /**
     * Serializes the extension
     *
     * @return Serialized extension
     */
    @Override
    public byte[] serializeExtensionContent() {
        appendBytes(message.getSignedTimestamp().getValue());
        LOGGER.debug("Serialized SignedCertificateTimestampExtension with timestamp of length "
                + message.getSignedTimestamp().getValue().length);
        return getAlreadySerialized();
    }

}
