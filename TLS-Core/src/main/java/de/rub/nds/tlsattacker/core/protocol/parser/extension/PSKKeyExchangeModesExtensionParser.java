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
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSKKeyExchangeModesExtensionMessage;

/**
 * RFC draft-ietf-tls-tls13-21
 */
public class PSKKeyExchangeModesExtensionParser extends ExtensionParser<PSKKeyExchangeModesExtensionMessage> {

    public PSKKeyExchangeModesExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(PSKKeyExchangeModesExtensionMessage msg) {
        LOGGER.debug("Parsing PSKKeyExchangeModesExtensionMessage");
        parseExchangeModesListLength(msg);
        parseExchangeModesBytes(msg);
        parseExchangeModesConfig(msg);
    }

    @Override
    protected PSKKeyExchangeModesExtensionMessage createExtensionMessage() {
        return new PSKKeyExchangeModesExtensionMessage();
    }

    private void parseExchangeModesListLength(PSKKeyExchangeModesExtensionMessage msg) {
        msg.setKeyExchangeModesListLength(parseIntField(ExtensionByteLength.PSK_KEY_EXCHANGE_MODES_LENGTH));
        LOGGER.debug("PSKKeyModesList length:" + msg.getKeyExchangeModesListLength().getValue());
    }

    private void parseExchangeModesBytes(PSKKeyExchangeModesExtensionMessage msg) {
        msg.setKeyExchangeModesListBytes(parseByteArrayField(msg.getKeyExchangeModesListLength().getValue()));
        LOGGER.debug("PSKKeyModesList bytes:"
                + ArrayConverter.bytesToHexString(msg.getKeyExchangeModesListBytes().getValue()));
    }

    private void parseExchangeModesConfig(PSKKeyExchangeModesExtensionMessage msg) {
        msg.setKeyExchangeModesConfig(msg.getKeyExchangeModesListBytes().getValue());
        LOGGER.debug("PSKKeyModesConfig bytes:" + ArrayConverter.bytesToHexString(msg.getKeyExchangeModesConfig()));
    }

}
