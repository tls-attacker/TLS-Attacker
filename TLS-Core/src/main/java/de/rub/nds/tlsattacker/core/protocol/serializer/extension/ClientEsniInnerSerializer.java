/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientEsniInner;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ClientEsniInnerSerializer extends Serializer<ClientEsniInner> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ClientEsniInner clientEsniInner;

    public ClientEsniInnerSerializer(ClientEsniInner clientEsniInner) {
        this.clientEsniInner = clientEsniInner;
    }

    @Override
    protected byte[] serializeBytes() {
        LOGGER.debug("Serializing ClientEsniInner");
        this.writeNonce(this.clientEsniInner);
        this.writeServerNameListLength(this.clientEsniInner);
        this.writeServerNameListBytes(this.clientEsniInner);
        this.writePadding(this.clientEsniInner);
        return getAlreadySerialized();
    }

    private void writeNonce(ClientEsniInner msg) {
        appendBytes(msg.getClientNonce().getValue());
        LOGGER.debug("Nonce: {}", msg.getClientNonce().getValue());
    }

    private void writeServerNameListLength(ClientEsniInner msg) {
        appendInt(
                clientEsniInner.getServerNameListLength().getValue(),
                ExtensionByteLength.SERVER_NAME_LIST);
        LOGGER.debug("ServerNameListLength: " + msg.getServerNameListLength().getValue());
    }

    private void writeServerNameListBytes(ClientEsniInner msg) {
        appendBytes(clientEsniInner.getServerNameListBytes().getValue());
        LOGGER.debug("ServerNameListBytes: {}", msg.getServerNameListBytes().getValue());
    }

    private void writePadding(ClientEsniInner msg) {
        appendBytes(clientEsniInner.getPadding().getValue());
        LOGGER.debug("Padding: {}", msg.getPadding().getValue());
    }
}
