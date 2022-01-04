/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

public class ServerNameIndicationExtensionParser extends ExtensionParser<ServerNameIndicationExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private List<ServerNamePair> pairList;

    public ServerNameIndicationExtensionParser(InputStream stream, Config config) {
        super(stream, config);
    }

    @Override
    public void parseExtensionMessageContent(ServerNameIndicationExtensionMessage msg) {
        if (getBytesLeft() > 0) {
            parseServerNameListLength(msg);
            parseServerNameListBytes(msg);
            pairList = new LinkedList<>();
            ByteArrayInputStream innerStream = new ByteArrayInputStream(msg.getServerNameListBytes().getValue());
            while (innerStream.available() > 0) {
                ServerNamePairParser parser = new ServerNamePairParser(innerStream);
                ServerNamePair pair = new ServerNamePair();
                parser.parse(pair);
                pairList.add(pair);
            }
            parseServerNameList(msg);
        } else {
            LOGGER.debug("Received empty SNI Extension");
        }
    }

    /**
     * Reads the next bytes as the serverNameListLength of the Extension and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseServerNameListLength(ServerNameIndicationExtensionMessage msg) {
        msg.setServerNameListLength(parseIntField(ExtensionByteLength.SERVER_NAME_LIST));
        LOGGER.debug("ServerNameListLength: " + msg.getServerNameListLength().getValue());
    }

    /**
     * Reads the next bytes as the serverNameListBytes of the Extension and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseServerNameListBytes(ServerNameIndicationExtensionMessage msg) {
        msg.setServerNameListBytes(parseByteArrayField(msg.getServerNameListLength().getValue()));
        LOGGER
                .debug("ServerNameListBytes: " + ArrayConverter.bytesToHexString(msg.getServerNameListBytes().getValue()));
    }

    /**
     * Reads the next bytes as the serverNameList of the Extension and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseServerNameList(ServerNameIndicationExtensionMessage msg) {
        msg.setServerNameList(pairList);
    }
}
