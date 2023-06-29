/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.EchClientHelloType;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.hpke.HpkeAeadFunction;
import de.rub.nds.tlsattacker.core.constants.hpke.HpkeKeyDerivationFunction;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedClientHelloExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ech.HpkeCipherSuite;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EncryptedClientHelloExtensionParser
        extends ExtensionParser<EncryptedClientHelloExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EncryptedClientHelloExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(EncryptedClientHelloExtensionMessage msg) {
        if (msg.getExtensionLength().getValue() == 0) {
            LOGGER.debug("Received empty ECH Extension");
            return;
        }
        if (getBytesLeft() == ExtensionByteLength.ECH_ACCEPT_CONFIRMATION_LENGTH) {
            // we assume that we received only the accept confirmation
            parseAcceptConfirmation(msg);
        } else {
            parseEchClientHelloType(msg);
            switch (msg.getEchClientHelloType()) {
                case OUTER:
                    // normal outer
                    parseHpkeCipherSuite(msg);
                    parseConfigId(msg);
                    parseEnc(msg);
                    parsePayload(msg);
                    break;
                case INNER:
                    // nothing to parse anymore
                    break;
                default:
                    LOGGER.warn("Received unknown clientHelloType in ECH extension");
            }
        }
    }

    private void parseEchClientHelloType(EncryptedClientHelloExtensionMessage msg) {
        byte[] echClientHelloTypeBytes =
                parseByteArrayField(ExtensionByteLength.ECH_CLIENT_HELLO_TYPE);
        EchClientHelloType echClientHelloType =
                EchClientHelloType.getEnumByByte(echClientHelloTypeBytes);
        msg.setEchClientHelloType(echClientHelloType);
        LOGGER.info("EchClientHelloType: " + echClientHelloType);
    }

    private void parseHpkeCipherSuite(EncryptedClientHelloExtensionMessage msg) {
        HpkeKeyDerivationFunction hkdfAlgorithm = parseKdfId();
        HpkeAeadFunction aeadAlgorithm = parseAEADId();
        HpkeCipherSuite hpkeCipherSuite = new HpkeCipherSuite(hkdfAlgorithm, aeadAlgorithm);
        msg.setHpkeCipherSuite(hpkeCipherSuite);
    }

    private HpkeKeyDerivationFunction parseKdfId() {
        byte[] kdfId = this.parseByteArrayField(ExtensionByteLength.ECH_CONFIG_KDF_ID);
        return HpkeKeyDerivationFunction.getEnumByByte(kdfId);
    }

    private HpkeAeadFunction parseAEADId() {
        byte[] aeadId = this.parseByteArrayField(ExtensionByteLength.ECH_CONFIG_AEAD_ID);
        return HpkeAeadFunction.getEnumByByte(aeadId);
    }

    private void parseConfigId(EncryptedClientHelloExtensionMessage msg) {
        int configId = this.parseIntField(ExtensionByteLength.ECH_CONFIG_ID);
        msg.setConfigId(configId);
        LOGGER.debug("Config ID: " + msg.getConfigId());
    }

    private void parseEnc(EncryptedClientHelloExtensionMessage msg) {
        int encLen = this.parseIntField(ExtensionByteLength.ECH_ENC_LENGTH);
        msg.setEncLength(encLen);
        byte[] enc = this.parseByteArrayField(encLen);
        msg.setEnc(enc);
        LOGGER.debug("Enc: " + msg.getEnc());
    }

    private void parsePayload(EncryptedClientHelloExtensionMessage msg) {
        int payloadLen = this.parseIntField(ExtensionByteLength.ECH_PAYLOAD_LENGTH);
        msg.setPayloadLength(payloadLen);
        byte[] payload = this.parseByteArrayField(payloadLen);
        msg.setPayload(payload);
        LOGGER.debug("Payload: " + msg.getPayload());
    }

    private void parseAcceptConfirmation(EncryptedClientHelloExtensionMessage msg) {
        byte[] acceptConfirmation =
                parseByteArrayField(ExtensionByteLength.ECH_ACCEPT_CONFIRMATION_LENGTH);
        msg.setAcceptConfirmation(acceptConfirmation);
    }
}
