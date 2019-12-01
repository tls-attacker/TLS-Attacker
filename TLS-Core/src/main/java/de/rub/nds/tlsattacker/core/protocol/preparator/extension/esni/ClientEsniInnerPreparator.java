/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension.esni;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.esni.ClientEsniInner;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ServerNamePairPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ServerNamePairSerializier;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.esni.ClientEsniInnerSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class ClientEsniInnerPreparator extends Preparator<ClientEsniInner> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final ClientEsniInner msg;
    private ByteArrayOutputStream serverNamePairListStream;

    public ClientEsniInnerPreparator(Chooser chooser, ClientEsniInner message) {
        super(chooser, message);
        this.msg = message;
        LOGGER.warn("EncryptedServerNameIndicationExtensionPreparator called. - ESNI not fully implemented yet");
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
        // TODO: Read from Config
        msg.setNonce(ArrayConverter.hexStringToByteArray("a7284c9a52f15c13644b947261774657"));
        LOGGER.debug("Nonce: " + ArrayConverter.bytesToHexString(msg.getNonce().getValue()));
    }

    private void prepareServerPariNameList(ClientEsniInner msg) {

        serverNamePairListStream = new ByteArrayOutputStream();
        for (ServerNamePair pair : msg.getServerNameList()) {
            ServerNamePairPreparator preparator = new ServerNamePairPreparator(chooser, pair);
            preparator.prepare();
            ServerNamePairSerializier serializer = new ServerNamePairSerializier(pair);
            try {
                serverNamePairListStream.write(serializer.serialize());
            } catch (IOException e) {
                throw new PreparationException("Could not write byte[] from ServerNamePair", e);
            }
        }
    }

    private void prepareServerNameListBytes(ClientEsniInner msg) {
        msg.setServerNameListBytes(serverNamePairListStream.toByteArray());
        LOGGER.debug("ServerNameListBytes: " + ArrayConverter.bytesToHexString(msg.getServerNameListBytes().getValue()));
    }

    private void prepareServerNameListLength(ClientEsniInner msg) {
        msg.setServerNameListLength(msg.getServerNameListBytes().getValue().length);
        LOGGER.debug("ServerNameListLength: " + msg.getServerNameListLength().getValue());
    }

    private void preparePadding(ClientEsniInner msg) {
        // TODO: Read from Context / Config / DNS // KeyRecord ?
        int paddedLength = 260;
        // TODO: Use constant instead ofliteral"2".
        int paddingLength = paddedLength - msg.getServerNameListBytes().getValue().length - 2;
        byte[] padding = new byte[paddingLength];
        msg.setPadding(padding);
        LOGGER.debug("Padding: " + ArrayConverter.bytesToHexString(msg.getPadding().getValue()));
    }

}
