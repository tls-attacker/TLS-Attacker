/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.UnknownExtensionMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnknownExtensionParser extends ExtensionParser<UnknownExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UnknownExtensionParser(InputStream inputStream, Config config) {
        super(inputStream, config);
    }

    protected void parseExtensionData(UnknownExtensionMessage message) {
        message.setExtensionData(parseByteArrayField(getBytesLeft()));
        LOGGER.debug("ExtensionData: " + ArrayConverter.bytesToHexString(message.getExtensionData().getValue()));
        message.setDataConfig(message.getExtensionData().getValue());

    }

    @Override
    public void parseExtensionMessageContent(UnknownExtensionMessage message) {
        parseExtensionData(message);
    }
}
