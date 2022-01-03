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
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.protocol.Parser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerNamePairParser extends Parser<ServerNamePair> {

    private static final Logger LOGGER = LogManager.getLogger();

    private ServerNamePair pair;

    public ServerNamePairParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public ServerNamePair parse() {
        pair = new ServerNamePair(null, null);
        parseServerNameType(pair);
        parseServerNameLength(pair);
        parseServerName(pair);
        pair.setServerNameConfig(pair.getServerName().getValue());
        pair.setServerNameTypeConfig(pair.getServerNameType().getValue());
        return pair;
    }

    /**
     * Reads the next bytes as the serverNameType of the Extension and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseServerNameType(ServerNamePair pair) {
        pair.setServerNameType(parseByteField(ExtensionByteLength.SERVER_NAME_TYPE));
        LOGGER.debug("ServerNameType: " + pair.getServerNameType().getValue());
    }

    /**
     * Reads the next bytes as the serverNameLength of the Extension and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseServerNameLength(ServerNamePair pair) {
        pair.setServerNameLength(parseIntField(ExtensionByteLength.SERVER_NAME));
        LOGGER.debug("ServerNameLength: " + pair.getServerNameLength().getValue());
    }

    /**
     * Reads the next bytes as the serverName of the Extension and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseServerName(ServerNamePair pair) {
        pair.setServerName(parseByteArrayField(pair.getServerNameLength().getValue()));
        LOGGER.debug("ServerName: " + ArrayConverter.bytesToHexString(pair.getServerName().getValue()));
    }

}
