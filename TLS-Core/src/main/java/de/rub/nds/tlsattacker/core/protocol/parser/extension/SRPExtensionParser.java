/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SRPExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;

public class SRPExtensionParser extends ExtensionParser<SRPExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SRPExtensionParser(InputStream stream, Config config) {
        super(stream, config);
    }

    @Override
    public void parseExtensionMessageContent(SRPExtensionMessage msg) {
        msg.setSrpIdentifierLength(parseIntField(ExtensionByteLength.SRP_IDENTIFIER_LENGTH));
        if (msg.getSrpIdentifierLength().getValue() > 32) {
            LOGGER.warn("The SRP Identifier should not exceed 32 bytes.");
        }
        msg.setSrpIdentifier(parseByteArrayField(msg.getSrpIdentifierLength().getValue()));
    }
}
