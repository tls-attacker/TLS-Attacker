/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ServerNamePairSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.LinkedList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerNameIndicationExtensionPreparator
        extends ExtensionPreparator<ServerNameIndicationExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ServerNameIndicationExtensionMessage msg;
    private ByteArrayOutputStream stream;

    public ServerNameIndicationExtensionPreparator(
            Chooser chooser, ServerNameIndicationExtensionMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing ServerNameIndicationExtensionMessage");
        stream = new ByteArrayOutputStream();
        prepareEntryList();
        prepareServerNameListBytes(msg);
        prepareServerNameListLength(msg);
    }

    public void prepareEntryList() {
        if (chooser.getConfig().getDefaultSniHostnames().isEmpty()) {
            if (chooser.getConnection().getHostname() == null) {
                prepareEmptyEntry();
            } else {
                prepareFromConnection();
            }
        } else {
            msg.setServerNameList(chooser.getConfig().getDefaultSniHostnames());
        }

        for (ServerNamePair pair : msg.getServerNameList()) {
            prepareEntry(chooser, pair);
        }
    }

    public void prepareEmptyEntry() {
        LOGGER.warn("Using emtpy list for SNI extension since no entries have been specified");
        byte[] emptyName = new byte[0];
        ServerNamePair emptyPair =
                new ServerNamePair(chooser.getConfig().getSniType().getValue(), emptyName);
        msg.setServerNameList(new LinkedList<>(Arrays.asList(emptyPair)));
        prepareEntry(chooser, emptyPair);
    }

    private void prepareFromConnection() {
        byte[] serverName =
                chooser.getConnection().getHostname().getBytes(Charset.forName("ASCII"));
        ServerNamePair namePair =
                new ServerNamePair(chooser.getConfig().getSniType().getValue(), serverName);
        msg.setServerNameList(new LinkedList<>(Arrays.asList(namePair)));
        prepareEntry(chooser, namePair);
    }

    private void prepareEntry(Chooser chooser, ServerNamePair namePair) {
        ServerNamePairPreparator namePairPreparator =
                new ServerNamePairPreparator(chooser, namePair);
        namePairPreparator.prepare();
        ServerNamePairSerializer serializer = new ServerNamePairSerializer(namePair);
        try {
            stream.write(serializer.serialize());
        } catch (IOException ex) {
            throw new PreparationException("Could not write byte[] from ServerNamePair", ex);
        }
    }

    private void prepareServerNameListBytes(ServerNameIndicationExtensionMessage msg) {
        msg.setServerNameListBytes(stream.toByteArray());
        LOGGER.debug("ServerNameListBytes: {}", msg.getServerNameListBytes().getValue());
    }

    private void prepareServerNameListLength(ServerNameIndicationExtensionMessage msg) {
        msg.setServerNameListLength(msg.getServerNameListBytes().getValue().length);
        LOGGER.debug("ServerNameListLength: " + msg.getServerNameListLength().getValue());
    }
}
