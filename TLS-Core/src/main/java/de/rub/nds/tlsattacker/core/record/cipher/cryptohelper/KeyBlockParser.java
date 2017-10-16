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
import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.protocol.parser.Parser;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
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
        try {
            KeySet keys = new KeySet();
            if (AlgorithmResolver.getCipherType(suite) != CipherType.AEAD) {
                parseClientWriteMacSecret(keys);
                parseServerWriteMacSecret(keys);
            }
            parseClientWriteKey(keys);
            parseServerWriteKey(keys);
            if (AlgorithmResolver.getCipherType(suite) == CipherType.BLOCK) {
                if (!version.usesExplicitIv()) {
                    parseClientWriteIvBlock(keys);
                    parseServerWriteIvBlock(keys);
                }
            } else if (AlgorithmResolver.getCipherType(suite) == CipherType.AEAD) {
                parseClientWriteIvAead(keys);
                parseServerWriteIvAead(keys);
            }
            return keys;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            throw new ParserException("Could not parse KeyBlock", ex);
        }
    }

    private int getAeadSaltSize() {
        return GCM_IV_LENGTH - SEQUENCE_NUMBER_LENGTH;
    }

    private void parseClientWriteIvBlock(KeySet keys) throws NoSuchAlgorithmException, NoSuchPaddingException {
        keys.setClientWriteIv(parseByteArrayField(getBlockSize()));
    }

    private void parseServerWriteIvBlock(KeySet keys) throws NoSuchAlgorithmException, NoSuchPaddingException {
        keys.setServerWriteIv(parseByteArrayField(getBlockSize()));
    }

    private void parseClientWriteIvAead(KeySet keys) throws NoSuchAlgorithmException, NoSuchPaddingException {
        keys.setClientWriteIv(parseByteArrayField(getAeadSaltSize()));
    }

    private void parseServerWriteIvAead(KeySet keys) throws NoSuchAlgorithmException, NoSuchPaddingException {
        keys.setServerWriteIv(parseByteArrayField(getAeadSaltSize()));
    }

    private void parseClientWriteKey(KeySet keys) throws NoSuchAlgorithmException {
        keys.setClientWriteKey(parseByteArrayField(getKeySize()));
    }

    private void parseServerWriteKey(KeySet keys) throws NoSuchAlgorithmException {
        keys.setServerWriteKey(parseByteArrayField(getKeySize()));
    }

    private void parseClientWriteMacSecret(KeySet keys) throws NoSuchAlgorithmException {
        keys.setClientWriteMacSecret(parseByteArrayField(getMacLength()));
    }

    private void parseServerWriteMacSecret(KeySet keys) throws NoSuchAlgorithmException {
        keys.setServerWriteMacSecret(parseByteArrayField(getMacLength()));
    }

    private int getMacLength() throws NoSuchAlgorithmException {
        MacAlgorithm macAlg = AlgorithmResolver.getMacAlgorithm(suite);
        return Mac.getInstance(macAlg.getJavaName()).getMacLength();
    }

    private int getKeySize() throws NoSuchAlgorithmException {
        CipherAlgorithm cipherAlg = AlgorithmResolver.getCipher(suite);
        return cipherAlg.getKeySize();
    }

    private int getBlockSize() throws NoSuchAlgorithmException, NoSuchPaddingException {
        CipherAlgorithm cipherAlg = AlgorithmResolver.getCipher(suite);
        return Cipher.getInstance(cipherAlg.getJavaName()).getBlockSize();
    }
}
