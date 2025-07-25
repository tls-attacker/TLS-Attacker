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
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.LinkedList;
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
        if (chooser.getConfig().getDefaultSniHostnames() == null) {
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

    public void prepareEmptyExtension() {
        LOGGER.debug("Preparing SNI extension with empty content.");
        msg.setServerNameList(new LinkedList<>());
        msg.setServerNameListBytes(new byte[0]);
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
