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
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientEsniInner;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ClientEsniInnerParser extends Parser<ClientEsniInner> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final ClientEsniInner clientEsniInner;

    public ClientEsniInnerParser(InputStream stream) {
        super(stream);
        clientEsniInner = new ClientEsniInner();
    }

    @Override
    public void parse(ClientEsniInner esniInner) {
        parseClientNonce(clientEsniInner);
        parseServerNameListLength(clientEsniInner);
        parseServerNameListByte(clientEsniInner);
        parsePadding(clientEsniInner);
        parseServerNameList(clientEsniInner);
    }

    private void parseClientNonce(ClientEsniInner clientEsniInner) {
        byte[] clientNonce = parseByteArrayField(ExtensionByteLength.NONCE);
        clientEsniInner.setClientNonce(clientNonce);
        LOGGER.debug("clientNonce: {}", clientEsniInner.getClientNonce().getValue());
    }

    private void parseServerNameListLength(ClientEsniInner clientEsniInner) {
        int serverNameListLength = parseIntField(ExtensionByteLength.SERVER_NAME_LIST);
        clientEsniInner.setServerNameListLength(serverNameListLength);
        LOGGER.debug(
                "serverNameListLength: " + clientEsniInner.getServerNameListLength().getValue());
    }

    private void parseServerNameListByte(ClientEsniInner clientEsniInner) {
        byte[] serverNameListByte =
                parseByteArrayField(clientEsniInner.getServerNameListLength().getValue());
        clientEsniInner.setServerNameListBytes(serverNameListByte);
        LOGGER.debug("serverNameListByte: {}", clientEsniInner.getServerNameListBytes().getValue());
    }

    private void parsePadding(ClientEsniInner clientEsniInner) {
        byte[] padding = parseByteArrayField(this.getBytesLeft());
        clientEsniInner.setPadding(padding);
        LOGGER.debug("padding: {}", clientEsniInner.getPadding().getValue());
    }

    private void parseServerNameList(ClientEsniInner clientEsniInner) {
        List<ServerNamePair> serverNamePairList = new LinkedList<>();
        ByteArrayInputStream innerStream =
                new ByteArrayInputStream(clientEsniInner.getServerNameListBytes().getValue());
        while (innerStream.available() > 0) {
            ServerNamePairParser parser = new ServerNamePairParser(innerStream);
            ServerNamePair pair = new ServerNamePair();
            parser.parse(pair);
            serverNamePairList.add(pair);
        }
        clientEsniInner.setServerNameList(serverNamePairList);
    }
}
