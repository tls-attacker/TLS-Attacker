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
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ServerNamePairSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.nio.charset.StandardCharsets;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerNameIndicationExtensionPreparator
        extends ExtensionPreparator<ServerNameIndicationExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ServerNameIndicationExtensionMessage msg;
    private SilentByteArrayOutputStream stream;

    public ServerNameIndicationExtensionPreparator(
            Chooser chooser, ServerNameIndicationExtensionMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing ServerNameIndicationExtensionMessage");
        stream = new SilentByteArrayOutputStream();

        if (chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
            prepareEntryList();
            prepareServerNameListBytes(msg);
            prepareServerNameListLength(msg);
        } else {
            prepareEmptyExtension();
        }
    }

    public void prepareEntryList() {
        if (msg.getServerNameList() == null || msg.getServerNameList().isEmpty()) {
            if (chooser.getConfig().getDefaultSniHostnames() != null) {
                prepareFromDefault();
            } else if (chooser.getConnection().getHostname() == null) {
                prepareEmptyEntry();
            } else {
                prepareFromConnection();
            }
        }

        for (ServerNamePair pair : msg.getServerNameList()) {
            prepareEntry(chooser, pair);
        }
    }

    public void prepareEmptyExtension() {
        LOGGER.debug("Preparing SNI extension with empty content.");
        msg.setServerNameList(new LinkedList<>());
        msg.setServerNameListBytes(new byte[0]);
    }

    public void prepareEmptyEntry() {
        LOGGER.warn("Using empty list for SNI extension since no entries have been specified");
        byte[] emptyName = new byte[0];
        ServerNamePair emptyPair =
                new ServerNamePair(chooser.getConfig().getSniType().getValue(), emptyName);
        msg.setServerNameList(new LinkedList<>(List.of(emptyPair)));
    }

    private void prepareFromConnection() {
        byte[] serverName =
                chooser.getConnection().getHostname().getBytes(StandardCharsets.US_ASCII);
        ServerNamePair namePair =
                new ServerNamePair(chooser.getConfig().getSniType().getValue(), serverName);
        msg.setServerNameList(new LinkedList<>(List.of(namePair)));
    }

    private void prepareFromDefault() {
        List<ServerNamePair> namePairs = new LinkedList<>();
        for (ServerNamePair namePair : chooser.getConfig().getDefaultSniHostnames()) {
            namePairs.add(
                    new ServerNamePair(
                            namePair.getServerNameTypeConfig(), namePair.getServerNameConfig()));
        }
        msg.setServerNameList(namePairs);
    }

    private void prepareEntry(Chooser chooser, ServerNamePair namePair) {
        ServerNamePairPreparator namePairPreparator =
                new ServerNamePairPreparator(chooser, namePair);
        namePairPreparator.prepare();
        ServerNamePairSerializer serializer = new ServerNamePairSerializer(namePair);
        stream.write(serializer.serialize());
    }

    private void prepareServerNameListBytes(ServerNameIndicationExtensionMessage msg) {
        msg.setServerNameListBytes(stream.toByteArray());
        LOGGER.debug("ServerNameListBytes: {}", msg.getServerNameListBytes().getValue());
    }

    private void prepareServerNameListLength(ServerNameIndicationExtensionMessage msg) {
        msg.setServerNameListLength(msg.getServerNameListBytes().getValue().length);
        LOGGER.debug("ServerNameListLength: {}", msg.getServerNameListLength().getValue());
    }
}
