/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.cipher.cryptohelper;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.parser.Parser;

public class KeyBlockParser extends Parser<KeySet> {

    /**
     * sequence Number length in byte
     */
    public static final int SEQUENCE_NUMBER_LENGTH = 8;

    /**
     * iv length in byte
     */
    public static final int GCM_IV_LENGTH = 12;

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
        return GCM_IV_LENGTH - SEQUENCE_NUMBER_LENGTH;
    }

    private void parseClientWriteIvBlock(KeySet keys) {
        keys.setClientWriteIv(parseByteArrayField(getIVSize()));
    }

    private void parseServerWriteIvBlock(KeySet keys) {
        keys.setServerWriteIv(parseByteArrayField(getIVSize()));
    }

    private void parseClientWriteIvAead(KeySet keys) {
        keys.setClientWriteIv(parseByteArrayField(getAeadSaltSize()));
    }

    private void parseServerWriteIvAead(KeySet keys) {
        keys.setServerWriteIv(parseByteArrayField(getAeadSaltSize()));
    }

    private void parseClientWriteKey(KeySet keys) {
        keys.setClientWriteKey(parseByteArrayField(getKeySize()));
    }

    private void parseServerWriteKey(KeySet keys) {
        keys.setServerWriteKey(parseByteArrayField(getKeySize()));
    }

    private void parseClientWriteMacSecret(KeySet keys) {
        keys.setClientWriteMacSecret(parseByteArrayField(getMacKeySize()));
    }

    private void parseServerWriteMacSecret(KeySet keys) {
        keys.setServerWriteMacSecret(parseByteArrayField(getMacKeySize()));
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
