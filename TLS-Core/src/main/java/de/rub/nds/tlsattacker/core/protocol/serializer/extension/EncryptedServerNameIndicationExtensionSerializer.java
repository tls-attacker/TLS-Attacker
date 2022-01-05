/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EncryptedServerNameIndicationExtensionSerializer
    extends ExtensionSerializer<EncryptedServerNameIndicationExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final EncryptedServerNameIndicationExtensionMessage msg;

    public EncryptedServerNameIndicationExtensionSerializer(EncryptedServerNameIndicationExtensionMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        LOGGER.debug("Serializing EncryptedServerNameIndicationExtensionMessage");
        switch (msg.getEsniMessageTypeConfig()) {
            case CLIENT:
                this.writeCipherSuite(msg);
                this.writeNamedGroup(msg);
                this.writeKeyExchangeLength(msg);
                this.writeKeyExchange(msg);
                this.writeRecordDigestLength(msg);
                this.writeRecordDigest(msg);
                this.writeEncryptedSniLength(msg);
                this.writeEncryptedSni(msg);
                break;
            case SERVER:
                writeCipherServerNonce(msg);
                break;
            default:
                break;
        }
        return getAlreadySerialized();
    }

    private void writeCipherServerNonce(EncryptedServerNameIndicationExtensionMessage msg) {
        appendBytes(msg.getServerNonce().getValue());
        LOGGER.debug("writeServerNonce: " + ArrayConverter.bytesToHexString(msg.getServerNonce().getValue()));
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
        appendInt(msg.getKeyShareEntry().getPublicKeyLength().getValue(), ExtensionByteLength.KEY_SHARE_LENGTH);
        LOGGER.debug("KeyExchangeLength: " + msg.getKeyShareEntry().getPublicKeyLength().getValue());

    }

    private void writeKeyExchange(EncryptedServerNameIndicationExtensionMessage msg) {
        appendBytes(msg.getKeyShareEntry().getPublicKey().getValue());
        LOGGER.debug(
            "KeyKeyShareEntry: " + ArrayConverter.bytesToHexString(msg.getKeyShareEntry().getPublicKey().getValue()));
    }

    private void writeRecordDigestLength(EncryptedServerNameIndicationExtensionMessage msg) {
        appendInt(msg.getRecordDigestLength().getValue(), ExtensionByteLength.RECORD_DIGEST_LENGTH);
        LOGGER.debug("RecordDigestLength: " + msg.getRecordDigestLength().getValue());
    }

    private void writeRecordDigest(EncryptedServerNameIndicationExtensionMessage msg) {
        appendBytes(msg.getRecordDigest().getValue());
        LOGGER.debug("RecordDigest: " + ArrayConverter.bytesToHexString(msg.getRecordDigest().getValue()));
    }

    private void writeEncryptedSniLength(EncryptedServerNameIndicationExtensionMessage msg) {
        appendInt(msg.getEncryptedSniLength().getValue(), ExtensionByteLength.ENCRYPTED_SNI_LENGTH);
        LOGGER.debug("EncryptedSniLength: " + msg.getEncryptedSniLength().getValue());
    }

    private void writeEncryptedSni(EncryptedServerNameIndicationExtensionMessage msg) {
        appendBytes(msg.getEncryptedSni().getValue());
        LOGGER.debug("EncryptedSni: " + ArrayConverter.bytesToHexString(msg.getEncryptedSni().getValue()));
    }
}