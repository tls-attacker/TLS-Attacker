/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSKKeyExchangeModesExtensionMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;

/**
 * RFC draft-ietf-tls-tls13-21
 */
public class PSKKeyExchangeModesExtensionParser extends ExtensionParser<PSKKeyExchangeModesExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PSKKeyExchangeModesExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(PSKKeyExchangeModesExtensionMessage msg) {
        LOGGER.debug("Parsing PSKKeyExchangeModesExtensionMessage");
        parseExchangeModesListLength(msg);
        parseExchangeModesBytes(msg);
        msg.setKeyExchangeModesConfig(msg.getKeyExchangeModesListBytes().getValue());
    }

    private void parseExchangeModesListLength(PSKKeyExchangeModesExtensionMessage msg) {
        msg.setKeyExchangeModesListLength(parseIntField(ExtensionByteLength.PSK_KEY_EXCHANGE_MODES_LENGTH));
        LOGGER.debug("PSKKeyModesList length:" + msg.getKeyExchangeModesListLength().getValue());
    }

    private void parseExchangeModesBytes(PSKKeyExchangeModesExtensionMessage msg) {
        msg.setKeyExchangeModesListBytes(parseByteArrayField(msg.getKeyExchangeModesListLength().getValue()));
        LOGGER.debug(
            "PSKKeyModesList bytes:" + ArrayConverter.bytesToHexString(msg.getKeyExchangeModesListBytes().getValue()));
    }

}
