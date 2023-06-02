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
import de.rub.nds.tlsattacker.core.protocol.message.extension.PWDProtectExtensionMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PWDProtectExtensionParser extends ExtensionParser<PWDProtectExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PWDProtectExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(PWDProtectExtensionMessage msg) {
        LOGGER.debug("Parsing PWDProtectExtensionMessage");
        parseUsernameLength(msg);
        parseUsername(msg);
    }

    /**
     * Reads the next bytes as the username length of the Extension and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseUsernameLength(PWDProtectExtensionMessage msg) {
        msg.setUsernameLength(parseIntField(ExtensionByteLength.PWD_NAME));
        LOGGER.debug("UsernameLength: " + msg.getUsernameLength().getValue());
    }

    /**
     * Reads the next bytes as the username of the Extension and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseUsername(PWDProtectExtensionMessage msg) {
        msg.setUsername(parseByteArrayField(msg.getUsernameLength().getValue()));
        LOGGER.debug("Username: {}", msg.getUsername());
    }
}
