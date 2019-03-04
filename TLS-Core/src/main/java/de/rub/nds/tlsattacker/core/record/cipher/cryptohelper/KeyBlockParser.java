/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.cipher.cryptohelper;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.parser.Parser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyBlockParser extends Parser<KeySet> {

    private final static Logger LOGGER = LogManager.getLogger();

    /**
     * sequence Number length in byte
     */
    public static final int SEQUENCE_NUMBER_LENGTH = 8;

    /**
     * AEAD iv length in byte
     */
    public static final int AEAD_IV_LENGTH = 12;

    private final CipherSuite suite;

    private final ProtocolVersion version;

    public KeyBlockParser(byte[] keyBlock, CipherSuite suite, ProtocolVersion version) {
        super(0, keyBlock);
        this.suite = suite;
        this.version = version;
    }

    @Override
    public KeySet parse() {
        KeySet keys = new KeySet();
        if (AlgorithmResolver.getCipherType(suite) != CipherType.AEAD) {
            parseClientWriteMacSecret(keys);
            parseServerWriteMacSecret(keys);
        }
        parseClientWriteKey(keys);
        parseServerWriteKey(keys);
        if ((AlgorithmResolver.getCipherType(suite) == CipherType.BLOCK && !version.usesExplicitIv())
                || suite.isSteamCipherWithIV()) {
            parseClientWriteIvBlock(keys);
            parseServerWriteIvBlock(keys);
        } else if (AlgorithmResolver.getCipherType(suite) == CipherType.AEAD) {
            parseClientWriteIvAead(keys);
            parseServerWriteIvAead(keys);
        }
        return keys;
    }

    private int getAeadSaltSize() {
        return AEAD_IV_LENGTH - AlgorithmResolver.getCipher(suite).getNonceBytesFromRecord();
    }

    private void parseClientWriteIvBlock(KeySet keys) {
        keys.setClientWriteIv(parseByteArrayField(getIVSize()));
        LOGGER.debug("ClientWriteIV: " + ArrayConverter.bytesToHexString(keys.getClientWriteIv()));
    }

    private void parseServerWriteIvBlock(KeySet keys) {
        keys.setServerWriteIv(parseByteArrayField(getIVSize()));
        LOGGER.debug("ServerWriteIV: " + ArrayConverter.bytesToHexString(keys.getServerWriteIv()));
    }

    private void parseClientWriteIvAead(KeySet keys) {
        keys.setClientWriteIv(parseByteArrayField(getAeadSaltSize()));
        LOGGER.debug("ClientWriteIV AEAD: " + ArrayConverter.bytesToHexString(keys.getClientWriteIv()));
    }

    private void parseServerWriteIvAead(KeySet keys) {
        keys.setServerWriteIv(parseByteArrayField(getAeadSaltSize()));
        LOGGER.debug("ServerWriteIV AEAD: " + ArrayConverter.bytesToHexString(keys.getServerWriteIv()));
    }

    private void parseClientWriteKey(KeySet keys) {
        keys.setClientWriteKey(parseByteArrayField(getKeySize()));
        LOGGER.debug("ClientWriteKey: " + ArrayConverter.bytesToHexString(keys.getClientWriteKey()));
    }

    private void parseServerWriteKey(KeySet keys) {
        keys.setServerWriteKey(parseByteArrayField(getKeySize()));
        LOGGER.debug("ServerWriteKey: " + ArrayConverter.bytesToHexString(keys.getServerWriteKey()));
    }

    private void parseClientWriteMacSecret(KeySet keys) {
        keys.setClientWriteMacSecret(parseByteArrayField(getMacKeySize()));
        LOGGER.debug("ClientMacKey: " + ArrayConverter.bytesToHexString(keys.getClientWriteMacSecret()));
    }

    private void parseServerWriteMacSecret(KeySet keys) {
        keys.setServerWriteMacSecret(parseByteArrayField(getMacKeySize()));
        LOGGER.debug("ServerMacKey: " + ArrayConverter.bytesToHexString(keys.getServerWriteMacSecret()));
    }

    private int getMacKeySize() {
        return AlgorithmResolver.getMacAlgorithm(version, suite).getKeySize();
    }

    private int getKeySize() {
        if (suite.isExportSymmetricCipher()) {
            return CipherSuite.EXPORT_SYMMETRIC_KEY_SIZE_BYTES;
        } else {
            return AlgorithmResolver.getCipher(suite).getKeySize();
        }
    }

    private int getIVSize() {
        return AlgorithmResolver.getCipher(suite).getNonceBytesFromHandshake();
    }

}
