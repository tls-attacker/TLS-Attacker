/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientEsniInner;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ServerNamePairSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ClientEsniInnerPreparator extends Preparator<ClientEsniInner> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final ClientEsniInner msg;
    private SilentByteArrayOutputStream serverNamePairListStream;

    public ClientEsniInnerPreparator(Chooser chooser, ClientEsniInner message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepare() {
        LOGGER.debug("Preparing ClientEsniInner");
        prepareNonce(msg);
        prepareServerPariNameList(msg);
        prepareServerNameListBytes(msg);
        prepareServerNameListLength(msg);
        preparePadding(msg);
    }

    private void prepareNonce(ClientEsniInner msg) {

        byte[] nonce = chooser.getEsniClientNonce();
        msg.setClientNonce(nonce);
        LOGGER.debug("Nonce: {}", msg.getClientNonce().getValue());
    }

    private void prepareServerPariNameList(ClientEsniInner msg) {

        serverNamePairListStream = new SilentByteArrayOutputStream();
        for (ServerNamePair pair : msg.getServerNameList()) {
            ServerNamePairPreparator preparator = new ServerNamePairPreparator(chooser, pair);
            preparator.prepare();
            ServerNamePairSerializer serializer = new ServerNamePairSerializer(pair);
            serverNamePairListStream.write(serializer.serialize());
        }
    }

    private void prepareServerNameListBytes(ClientEsniInner msg) {
        msg.setServerNameListBytes(serverNamePairListStream.toByteArray());
        LOGGER.debug("ServerNameListBytes: {}", msg.getServerNameListBytes().getValue());
    }

    private void prepareServerNameListLength(ClientEsniInner msg) {
        msg.setServerNameListLength(msg.getServerNameListBytes().getValue().length);
        LOGGER.debug("ServerNameListLength: {}", msg.getServerNameListLength().getValue());
    }

    private void preparePadding(ClientEsniInner msg) {
        byte[] padding;
        int paddedLength = chooser.getEsniPaddedLength();
        int paddingLength =
                paddedLength
                        - msg.getServerNameListBytes().getValue().length
                        - ExtensionByteLength.SERVER_NAME_LIST;
        if (paddingLength > 65536) {
            LOGGER.warn("ESNI Inner PaddingLength is greater than 65536. Limiting it to 65536");
            paddingLength = 65536;
        }
        if (paddingLength > 0) {
            padding = new byte[paddingLength];
        } else {
            padding = new byte[0];
        }
        msg.setPadding(padding);
        LOGGER.debug("PaddedLength: {}", paddedLength);
        LOGGER.debug("Padding: {}", msg.getPadding().getValue());
    }
}
