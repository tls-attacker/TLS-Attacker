/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler.LOGGER;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignedCertificateTimestampExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SignedCertificateTimestampExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.SignedCertificateTimestampExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SignedCertificateTimestampExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class SignedCertificateTimestampExtensionHandler extends
        ExtensionHandler<SignedCertificateTimestampExtensionMessage> {

    /**
     * Constructor
     *
     * @param context
     *            A TlsContext
     */
    public SignedCertificateTimestampExtensionHandler(TlsContext context) {
        super(context);
    }

    /**
     * Returns a new SignedCertificateTimestampExtensionParser
     *
     * @param message
     *            Message which holds the extensions
     * @param pointer
     *            Startposition of the extension
     * @return A SignedCertificateTimestampExtensionParser
     */
    @Override
    public ExtensionParser getParser(byte[] message, int pointer) {
        LOGGER.debug("The signed certificate timestamp extension handler returned the parser.");
        return new SignedCertificateTimestampExtensionParser(pointer, message);
    }

    /**
     * Returns a new SignedCertificateTimestampExtensionPreparator
     *
     * @param message
     *            A SignedCertificateTimestampExtensionMessage
     * @return A SignedCertificateTimestampExtensionPreparator
     */
    @Override
    public ExtensionPreparator getPreparator(SignedCertificateTimestampExtensionMessage message) {
        LOGGER.debug("The signed certificate timestamp extension handler returned the preparator.");
        return new SignedCertificateTimestampExtensionPreparator(context, message);
    }

    /**
     * Returns a new SignedCertificateTimestampExtensionSerializer
     *
     * @param message
     *            A SignedCertificateTimestampExtensionMessage
     * @return A SignedCertificateTimestampExtensionSerializer
     */
    @Override
    public ExtensionSerializer getSerializer(SignedCertificateTimestampExtensionMessage message) {
        LOGGER.debug("The signed certificate timestamp extension handler returned the serializer.");
        return new SignedCertificateTimestampExtensionSerializer(message);
    }

    /**
     * Parses the content of a SignedCertificateTimestampExtensionMessage to the
     * actual TlsContext
     *
     * @param message
     *            A SingedCertificateImestampExtensionMessage
     */
    @Override
    public void adjustTLSContext(SignedCertificateTimestampExtensionMessage message) {
        if (message.getExtensionLength().getValue() > 65535) {
            LOGGER.warn("The SingedCertificateTimestamp length shouldn't exceed 2 bytes as defined in RFC 6962. "
                    + "Length was " + message.getExtensionLength().getValue());
        }
        context.setSignedCertificateTimestamp(message.getSignedTimestamp().getValue());
        LOGGER.debug("The signed certificate timestamp extension handler adjusted the TLS context.");
    }

}
