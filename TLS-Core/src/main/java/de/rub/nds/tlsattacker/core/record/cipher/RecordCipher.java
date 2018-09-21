/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.cipher;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.BulkCipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.crypto.cipher.DecryptionCipher;
import de.rub.nds.tlsattacker.core.crypto.cipher.EncryptionCipher;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.DecryptionRequest;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.DecryptionResult;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.EncryptionRequest;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.EncryptionResult;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class RecordCipher {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * cipher for decryption
     */
    protected DecryptionCipher decryptCipher;
    /**
     * cipher for encryption
     */
    protected EncryptionCipher encryptCipher;
    /**
     * CipherAlgorithm algorithm (AES, ...)
     */
    protected final BulkCipherAlgorithm bulkCipherAlg;

    private final KeySet keySet;
    /**
     * TLS context
     */
    protected TlsContext context;

    protected final CipherSuite cipherSuite;

    protected final ProtocolVersion version;

    public RecordCipher(TlsContext context, KeySet keySet) {
        this.keySet = keySet;
        this.context = context;
        this.cipherSuite = context.getChooser().getSelectedCipherSuite();
        this.version = context.getChooser().getSelectedProtocolVersion();
        this.bulkCipherAlg = AlgorithmResolver.getBulkCipherAlgorithm(context.getChooser().getSelectedCipherSuite());
    }

    public abstract EncryptionResult encrypt(EncryptionRequest encryptionRequest);

    public abstract DecryptionResult decrypt(DecryptionRequest decryptionRequest);

    public abstract boolean isUsingPadding();

    public abstract boolean isUsingMac();

    public abstract boolean isUsingTags();

    public int getTagSize() {
        return 0;
    }

    public byte[] calculateMac(byte[] data, ConnectionEndType connectionEndType) {
        return new byte[0];
    }

    public int getMacLength() {
        return 0;
    }

    public byte[] calculatePadding(int paddingLength) {
        return new byte[0];
    }

    public int calculatePaddingLength(int dataLength) {
        return 0;
    }

    public final KeySet getKeySet() {
        return keySet;
    }

    public abstract byte[] getEncryptionIV();

    public abstract byte[] getDecryptionIV();
}
