/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record.cipher;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordCipherFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    public static RecordCipher getRecordCipher(
            TlsContext tlsContext, KeySet keySet, CipherSuite cipherSuite, byte[] connectionId) {
        try {
            if (tlsContext.getChooser().getSelectedCipherSuite() == null
                    || !cipherSuite.isImplemented()) {
                LOGGER.warn(
                        "Cipher "
                                + cipherSuite.name()
                                + " not implemented. Using Null Cipher instead");
                return getNullCipher(tlsContext);
            } else {
                CipherType type = AlgorithmResolver.getCipherType(cipherSuite);
                CipherState state =
                        new CipherState(
                                tlsContext.getChooser().getSelectedProtocolVersion(),
                                cipherSuite,
                                keySet,
                                tlsContext.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC),
                                connectionId);
                switch (type) {
                    case AEAD:
                        return new RecordAEADCipher(tlsContext, state);
                    case BLOCK:
                        return new RecordBlockCipher(tlsContext, state);
                    case STREAM:
                        return new RecordStreamCipher(tlsContext, state);
                    default:
                        LOGGER.warn("UnknownCipherType:" + type.name());
                        return new RecordNullCipher(tlsContext, state);
                }
            }
        } catch (Exception e) {
            LOGGER.debug(
                    "Could not create RecordCipher from the current Context! Creating null Cipher",
                    e);
            return getNullCipher(tlsContext);
        }
    }

    public static RecordCipher getRecordCipher(
            TlsContext tlsContext, KeySet keySet, boolean isForEncryption) {
        return getRecordCipher(
                tlsContext,
                keySet,
                tlsContext.getChooser().getSelectedCipherSuite(),
                isForEncryption
                        ? tlsContext.getWriteConnectionId()
                        : tlsContext.getReadConnectionId());
    }

    public static RecordNullCipher getNullCipher(TlsContext tlsContext) {
        return new RecordNullCipher(
                tlsContext,
                new CipherState(
                        tlsContext.getChooser().getSelectedProtocolVersion(),
                        tlsContext.getChooser().getSelectedCipherSuite(),
                        null,
                        null,
                        null));
    }

    private RecordCipherFactory() {}
}
