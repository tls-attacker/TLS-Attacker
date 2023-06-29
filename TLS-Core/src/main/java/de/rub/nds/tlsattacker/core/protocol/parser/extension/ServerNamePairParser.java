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
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerNamePairParser extends Parser<ServerNamePair> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServerNamePairParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(ServerNamePair pair) {
        parseServerNameType(pair);
        parseServerNameLength(pair);
        parseServerName(pair);
        pair.setServerNameConfig(pair.getServerName().getValue());
        pair.setServerNameTypeConfig(pair.getServerNameType().getValue());
    }

    /**
     * Reads the next bytes as the serverNameType of the Extension and writes them in the message
     */
    private void parseServerNameType(ServerNamePair pair) {
        pair.setServerNameType(parseByteField(ExtensionByteLength.SERVER_NAME_TYPE));
        LOGGER.debug("ServerNameType: " + pair.getServerNameType().getValue());
    }

    /**
     * Reads the next bytes as the serverNameLength of the Extension and writes them in the message
     */
    private void parseServerNameLength(ServerNamePair pair) {
        pair.setServerNameLength(parseIntField(ExtensionByteLength.SERVER_NAME));
        LOGGER.debug("ServerNameLength: " + pair.getServerNameLength().getValue());
    }

    /** Reads the next bytes as the serverName of the Extension and writes them in the message */
    private void parseServerName(ServerNamePair pair) {
        pair.setServerName(parseByteArrayField(pair.getServerNameLength().getValue()));
        LOGGER.debug("ServerName: {}", pair.getServerName().getValue());
    }
}
