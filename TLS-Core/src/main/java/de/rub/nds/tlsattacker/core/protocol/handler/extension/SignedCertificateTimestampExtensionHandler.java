/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignedCertificateTimestampExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SignedCertificateTimestampExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.SignedCertificateTimestampExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SignedCertificateTimestampExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SignedCertificateTimestampExtensionHandler
    extends ExtensionHandler<SignedCertificateTimestampExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor
     *
     * @param context
     *                A Chooser
     */
    public SignedCertificateTimestampExtensionHandler(TlsContext context) {
        super(context);
    }

    /**
     * Returns a new SignedCertificateTimestampExtensionParser
     *
     * @param  message
     *                 Message which holds the extensions
     * @param  pointer
     *                 Startposition of the extension
     * @return         A SignedCertificateTimestampExtensionParser
     */
    @Override
    public SignedCertificateTimestampExtensionParser getParser(byte[] message, int pointer, Config config) {
        return new SignedCertificateTimestampExtensionParser(pointer, message, config);
    }

    /**
     * Returns a new SignedCertificateTimestampExtensionPreparator
     *
     * @param  message
     *                 A SignedCertificateTimestampExtensionMessage
     * @return         A SignedCertificateTimestampExtensionPreparator
     */
    @Override
    public SignedCertificateTimestampExtensionPreparator
        getPreparator(SignedCertificateTimestampExtensionMessage message) {
        return new SignedCertificateTimestampExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    /**
     * Returns a new SignedCertificateTimestampExtensionSerializer
     *
     * @param  message
     *                 A SignedCertificateTimestampExtensionMessage
     * @return         A SignedCertificateTimestampExtensionSerializer
     */
    @Override
    public SignedCertificateTimestampExtensionSerializer
        getSerializer(SignedCertificateTimestampExtensionMessage message) {
        return new SignedCertificateTimestampExtensionSerializer(message);
    }

    /**
     * Parses the content of a SignedCertificateTimestampExtensionMessage to the actual Chooser
     *
     * @param message
     *                A SingedCertificateTimestampExtensionMessage
     */
    @Override
    public void adjustTLSExtensionContext(SignedCertificateTimestampExtensionMessage message) {
        if (message.getExtensionLength().getValue() > 65535) {
            LOGGER.warn("The SingedCertificateTimestamp length shouldn't exceed 2 bytes as defined in RFC 6962. "
                + "Length was " + message.getExtensionLength().getValue());
        }
        context.setSignedCertificateTimestamp(message.getSignedTimestamp().getValue());
        LOGGER.debug("The context SignedCertificateTimestamp was set to "
            + ArrayConverter.bytesToHexString(message.getSignedTimestamp()));
    }

}
