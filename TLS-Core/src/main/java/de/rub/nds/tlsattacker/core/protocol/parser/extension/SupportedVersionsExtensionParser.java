/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;

public class SupportedVersionsExtensionParser extends ExtensionParser<SupportedVersionsExtensionMessage> {

    public SupportedVersionsExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(SupportedVersionsExtensionMessage msg) {
        LOGGER.debug("Parsing SupportedVersionsExtensionMessage");
        parseSupportedVersionLength(msg);
        parseSupportedVersion(msg);
    }

    @Override
    protected SupportedVersionsExtensionMessage createExtensionMessage() {
        return new SupportedVersionsExtensionMessage();
    }

    /**
     * Reads the next bytes as the supportedVersionLength of the Extension and
     * writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSupportedVersionLength(SupportedVersionsExtensionMessage msg) {
        msg.setSupportedVersionsLength(parseIntField(ExtensionByteLength.SUPPORTED_PROTOCOL_VERSIONS_LENGTH));
        LOGGER.debug("SupportedVersionsLength: " + msg.getSupportedVersionsLength().getValue());
    }

    /**
     * Reads the next bytes as the supportedVersion of the Extension and writes
     * them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSupportedVersion(SupportedVersionsExtensionMessage msg) {
        msg.setSupportedVersions(parseByteArrayField(msg.getSupportedVersionsLength().getValue()));
        LOGGER.debug("SupportedVersions: " + ArrayConverter.bytesToHexString(msg.getSupportedVersions().getValue()));
    }
}