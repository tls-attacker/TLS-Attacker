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
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PasswordSaltExtensionMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PasswordSaltExtensionParser extends ExtensionParser<PasswordSaltExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PasswordSaltExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(PasswordSaltExtensionMessage msg) {
        LOGGER.debug("Parsing PasswordSaltExtensionMessage");
        parseSaltLength(msg);
        parseSalt(msg);
    }

    private void parseSaltLength(PasswordSaltExtensionMessage msg) {
        msg.setSaltLength(parseIntField(ExtensionByteLength.PASSWORD_SALT));
        LOGGER.debug("SaltLength: " + msg.getSaltLength().getValue());
    }

    private void parseSalt(PasswordSaltExtensionMessage msg) {
        msg.setSalt(parseByteArrayField(msg.getSaltLength().getValue()));
        LOGGER.debug("Salt: {}", msg.getSalt());
    }
}
