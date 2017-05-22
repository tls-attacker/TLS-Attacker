/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;

/**
 * @author Nurullah Erinola
 */
public class SupportedVersionsExtensionParser extends ExtensionParser<SupportedVersionsExtensionMessage> {

    public SupportedVersionsExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(SupportedVersionsExtensionMessage msg) {
        msg.setSupportedVersionsLength(parseIntField(ExtensionByteLength.SUPPORTED_PROTOCOL_VERSIONS_LENGTH));
        msg.setSupportedVersions(parseByteArrayField(msg.getSupportedVersionsLength().getValue()));
    }

    @Override
    protected SupportedVersionsExtensionMessage createExtensionMessage() {
        return new SupportedVersionsExtensionMessage();
    }
}