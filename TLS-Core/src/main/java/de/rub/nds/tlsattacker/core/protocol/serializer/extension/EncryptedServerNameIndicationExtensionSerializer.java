/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.esni.ClientEsniInner;

public class EncryptedServerNameIndicationExtensionSerializer extends
        ExtensionSerializer<EncryptedServerNameIndicationExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final EncryptedServerNameIndicationExtensionMessage msg;

    public EncryptedServerNameIndicationExtensionSerializer(EncryptedServerNameIndicationExtensionMessage message) {
        super(message);
        this.msg = message;
        // LOGGER.warn("EncryptedServerNameIndicationExtensionSerializer called. - ESNI implemented yet");
    }

    @Override
    public byte[] serializeExtensionContent() {
        LOGGER.debug("Serializing ncryptedServerNameIndicationExtensionMessage");

        this.writeCipherSuite(msg);

        this.writeNamedGroup(msg);
        this.writeKeyExchangeLength(msg);
        this.writeKeyExchange(msg);

        this.writeRecordDigestLength(msg);
        this.writeRecordDigest(msg);

        this.writeEncryptedSniLength(msg);
        this.writeEncryptedSni(msg);

        return getAlreadySerialized();
    }

    private void writeCipherSuite(EncryptedServerNameIndicationExtensionMessage msg) {
        appendBytes(msg.getCipherSuite().getValue());
        LOGGER.debug("CipherSuite: " + ArrayConverter.bytesToHexString(msg.getCipherSuite().getValue()));
    }

    private void writeNamedGroup(EncryptedServerNameIndicationExtensionMessage msg) {
        appendBytes(msg.getKeyShareEntry().getGroup().getValue());
        LOGGER.debug("NamedGroup: " + ArrayConverter.bytesToHexString(msg.getKeyShareEntry().getGroup().getValue()));
    }

    private void writeKeyExchangeLength(EncryptedServerNameIndicationExtensionMessage msg) {
        // TODO: use constant
        appendInt(msg.getKeyShareEntry().getPublicKeyLength().getValue(), 2);
        LOGGER.debug("KeyExchangeLength: " + msg.getKeyShareEntry().getPublicKeyLength().getValue());

    }

    private void writeKeyExchange(EncryptedServerNameIndicationExtensionMessage msg) {
        appendBytes(msg.getKeyShareEntry().getPublicKey().getValue());
        LOGGER.debug("KeyKeyShareEntry: "
                + ArrayConverter.bytesToHexString(msg.getKeyShareEntry().getPublicKey().getValue()));

    }

    private void writeRecordDigestLength(EncryptedServerNameIndicationExtensionMessage msg) {
        // TODO: use constant
        appendInt(msg.getRecordDigestLength().getValue(), 2);
        LOGGER.debug("RecordDigestLength: " + msg.getRecordDigestLength().getValue());
    }

    private void writeRecordDigest(EncryptedServerNameIndicationExtensionMessage msg) {
        appendBytes(msg.getRecordDigest().getValue());
        LOGGER.debug("RecordDigest: " + ArrayConverter.bytesToHexString(msg.getRecordDigest().getValue()));
    }

    private void writeEncryptedSniLength(EncryptedServerNameIndicationExtensionMessage msg) {
        // TODO: use constant
        appendInt(msg.getEncryptedSniLength().getValue(), 2);
        LOGGER.debug("EncryptedSniLength: " + msg.getEncryptedSniLength().getValue());
    }

    private void writeEncryptedSni(EncryptedServerNameIndicationExtensionMessage msg) {
        appendBytes(msg.getEncryptedSni().getValue());
        LOGGER.debug("EncryptedSni: " + ArrayConverter.bytesToHexString(msg.getEncryptedSni().getValue()));
    }
}