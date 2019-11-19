/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import java.io.ByteArrayOutputStream;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.esni.ClientEncryptedSni;
import de.rub.nds.tlsattacker.core.protocol.message.extension.esni.ClientEsniInner;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.esni.ClientEncryptedSniPreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.esni.ClientEsniInnerPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.esni.ClientEncryptedSniSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.esni.ClientEsniInnerSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class EncryptedServerNameIndicationExtensionPreparator extends
        ExtensionPreparator<EncryptedServerNameIndicationExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final EncryptedServerNameIndicationExtensionMessage msg;
    private ByteArrayOutputStream stream;

    public EncryptedServerNameIndicationExtensionPreparator(Chooser chooser,
            EncryptedServerNameIndicationExtensionMessage message,
            ExtensionSerializer<EncryptedServerNameIndicationExtensionMessage> serializer) {
        super(chooser, message, serializer);

        this.msg = message;
        LOGGER.warn("EncryptedServerNameIndicationExtensionPreparator called. - ESNI implemented yet");
    }

    @Override
    public void prepareExtensionContent() {
        this.prepareServerNameListBytes(this.msg);
        this.prepareClientEsniInner(this.msg);
        this.prepareClientEsniInnerBytes(this.msg);
        this.prepareClientEncryptedSni(this.msg);
        this.prepareClientEncryptedSniBytes(this.msg);
    }

    private void prepareServerNamePairList() {
        // TODO Copy from SNI Extension
    }

    private void prepareServerNameListBytes(EncryptedServerNameIndicationExtensionMessage msg) {
        // TODO Copy from SNI Extension
    }

    private void prepareClientEsniInner(EncryptedServerNameIndicationExtensionMessage msg) {
        ClientEsniInner clientEsniInner = msg.getClientEsniInner();
        // clientEsniInner.setServerNameListBytes(msg.getServerNameListBytes().getValue());
        ClientEsniInnerPreparator preparator = new ClientEsniInnerPreparator(this.chooser, clientEsniInner);
        preparator.prepare();
    }

    private void prepareClientEsniInnerBytes(EncryptedServerNameIndicationExtensionMessage msg) {
        ClientEsniInnerSerializer serializer = new ClientEsniInnerSerializer(msg.getClientEsniInner());
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        // stream.write(serializer.serialize());
        msg.setClientEsniInnerBytes(stream.toByteArray());
    }

    private void prepareClientEncryptedSni(EncryptedServerNameIndicationExtensionMessage msg) {
        ClientEncryptedSni clientEncryptedSni = msg.getClientEncryptedSni();
        // clientEncryptedSni.setClientEsniInnerBytes(msg.getClientEsniInnerBytes().getValue());
        ClientEncryptedSniPreparator preparator = new ClientEncryptedSniPreparator(this.chooser, clientEncryptedSni);
        preparator.prepare();

    }

    private void prepareClientEncryptedSniBytes(EncryptedServerNameIndicationExtensionMessage msg) {
        ClientEncryptedSniSerializer clientEncryptedSniSerializer = new ClientEncryptedSniSerializer(
                msg.getClientEncryptedSni());
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        // stream.write(serializer.serialize());
        msg.setClientEncryptedSniBytes(stream.toByteArray());
    }
}