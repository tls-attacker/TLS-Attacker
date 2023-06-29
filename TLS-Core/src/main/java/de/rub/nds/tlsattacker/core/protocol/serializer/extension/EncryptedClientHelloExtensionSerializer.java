/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.hpke.HpkeAeadFunction;
import de.rub.nds.tlsattacker.core.constants.hpke.HpkeKeyDerivationFunction;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedClientHelloExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ech.HpkeCipherSuite;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EncryptedClientHelloExtensionSerializer
        extends ExtensionSerializer<EncryptedClientHelloExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final EncryptedClientHelloExtensionMessage msg;

    public EncryptedClientHelloExtensionSerializer(EncryptedClientHelloExtensionMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        switch (msg.getEchClientHelloType()) {
            case INNER:
                writeEchClientHelloType(msg);
                if (msg.getAcceptConfirmation() != null) {
                    writeAcceptConfirmation(msg);
                }
                break;
            case OUTER:
                writeEchClientHelloType(msg);
                writeHpkeCipherSuite(msg);
                writeConfigId(msg);
                writeEncLen(msg);
                writeEnc(msg);
                writePayloadLen(msg);
                writePayload(msg);
        }
        return getAlreadySerialized();
    }

    private void writeEchClientHelloType(EncryptedClientHelloExtensionMessage msg) {
        appendBytes(msg.getEchClientHelloType().getByteValue());
        LOGGER.debug(
                "Write EchClientHelloType: "
                        + ArrayConverter.bytesToHexString(
                                msg.getEchClientHelloType().getByteValue()));
    }

    private void writeHpkeCipherSuite(EncryptedClientHelloExtensionMessage msg) {
        HpkeCipherSuite cipherSuite = msg.getHpkeCipherSuite();
        HpkeAeadFunction aeadFunction = cipherSuite.getAeadFunction();
        HpkeKeyDerivationFunction keyDerivationFunction = cipherSuite.getKeyDerivationFunction();
        appendBytes(keyDerivationFunction.getByteValue());
        appendBytes(aeadFunction.getByteValue());
        LOGGER.debug(
                "HPKE Ciphersuite: "
                        + ArrayConverter.bytesToHexString(
                                ArrayConverter.concatenate(
                                        keyDerivationFunction.getByteValue(),
                                        aeadFunction.getByteValue())));
    }

    private void writeConfigId(EncryptedClientHelloExtensionMessage msg) {
        appendBytes(msg.getConfigId().getByteArray(ExtensionByteLength.ECH_CONFIG_ID));
        LOGGER.debug(
                "Config Id: "
                        + ArrayConverter.bytesToHexString(
                                msg.getConfigId().getByteArray(ExtensionByteLength.ECH_CONFIG_ID)));
    }

    private void writeEncLen(EncryptedClientHelloExtensionMessage msg) {
        appendBytes(msg.getEncLength().getByteArray(ExtensionByteLength.ECH_ENC_LENGTH));
        LOGGER.debug(
                "Enc Length: "
                        + ArrayConverter.bytesToHexString(
                                msg.getEncLength()
                                        .getByteArray(ExtensionByteLength.ECH_ENC_LENGTH)));
    }

    private void writeEnc(EncryptedClientHelloExtensionMessage msg) {
        appendBytes(msg.getEnc().getValue());
        LOGGER.debug("Enc: " + ArrayConverter.bytesToHexString(msg.getEnc().getValue()));
    }

    private void writePayloadLen(EncryptedClientHelloExtensionMessage msg) {
        appendBytes(msg.getPayloadLength().getByteArray(ExtensionByteLength.ECH_PAYLOAD_LENGTH));
        LOGGER.debug(
                "Payload Length: "
                        + ArrayConverter.bytesToHexString(
                                msg.getPayloadLength()
                                        .getByteArray(ExtensionByteLength.ECH_PAYLOAD_LENGTH)));
    }

    private void writePayload(EncryptedClientHelloExtensionMessage msg) {
        appendBytes(msg.getPayload().getValue());
        LOGGER.debug("Payload: " + ArrayConverter.bytesToHexString(msg.getPayload().getValue()));
    }

    private void writeAcceptConfirmation(EncryptedClientHelloExtensionMessage msg) {
        appendBytes(msg.getAcceptConfirmation().getValue());
        LOGGER.debug(
                "Accept Confirmation: "
                        + ArrayConverter.bytesToHexString(msg.getAcceptConfirmation().getValue()));
    }
}
