/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SupportedVersionsExtensionParser
        extends ExtensionParser<SupportedVersionsExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SupportedVersionsExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(SupportedVersionsExtensionMessage msg) {
        LOGGER.debug("Parsing SupportedVersionsExtensionMessage");
        if (getTlsContext().getTalkingConnectionEndType() == ConnectionEndType.SERVER) {
            msg.setSupportedVersions(parseByteArrayField(HandshakeByteLength.VERSION));
            LOGGER.debug("Supported version: {}", msg.getSupportedVersions().getValue());
        } else {
            parseSupportedVersionLength(msg);
            parseSupportedVersion(msg);
        }
    }

    /**
     * Reads the next bytes as the supportedVersionLength of the Extension and writes them in the
     * message
     *
     * @param msg Message to write in
     */
    private void parseSupportedVersionLength(SupportedVersionsExtensionMessage msg) {
        msg.setSupportedVersionsLength(
                parseIntField(ExtensionByteLength.SUPPORTED_PROTOCOL_VERSIONS_LENGTH));
        LOGGER.debug("SupportedVersionsLength: " + msg.getSupportedVersionsLength().getValue());
    }

    /**
     * Reads the next bytes as the supportedVersion of the Extension and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseSupportedVersion(SupportedVersionsExtensionMessage msg) {
        msg.setSupportedVersions(parseByteArrayField(msg.getSupportedVersionsLength().getValue()));
        LOGGER.debug("SupportedVersions: {}", msg.getSupportedVersions().getValue());
    }
}
