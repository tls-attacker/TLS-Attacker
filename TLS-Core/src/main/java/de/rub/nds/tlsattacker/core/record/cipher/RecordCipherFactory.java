/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.record.cipher;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordCipherFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    public static RecordCipher getRecordCipher(TlsContext context, KeySet keySet, CipherSuite cipherSuite,
        boolean isEncCipher) {
        int epoch =
            isEncCipher ? context.getRecordLayer().getNextWriteEpoch() : context.getRecordLayer().getNextReadEpoch();
        try {
            if (context.getChooser().getSelectedCipherSuite() == null || !cipherSuite.isImplemented()) {
                LOGGER.warn("Cipher " + cipherSuite.name() + " not implemented. Using Null Cipher instead");
                return new RecordNullCipher(context, new CipherState(context.getChooser().getSelectedProtocolVersion(),
                    context.getChooser().getSelectedCipherSuite(), null, null, epoch));
            } else {
                CipherType type = AlgorithmResolver.getCipherType(cipherSuite);
                CipherState state = new CipherState(context.getChooser().getSelectedProtocolVersion(),
                    context.getChooser().getSelectedCipherSuite(), keySet,
                    context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC), epoch);
                switch (type) {
                    case AEAD:
                        return new RecordAEADCipher(context, state);
                    case BLOCK:
                        return new RecordBlockCipher(context, state);
                    case STREAM:
                        return new RecordStreamCipher(context, state);
                    default:
                        LOGGER.warn("UnknownCipherType:" + type.name());
                        return new RecordNullCipher(context, state);
                }
            }
        } catch (Exception e) {
            LOGGER.debug("Could not create RecordCipher from the current Context! Creating null Cipher", e);
            return new RecordNullCipher(context, new CipherState(context.getChooser().getSelectedProtocolVersion(),
                context.getChooser().getSelectedCipherSuite(), null, null, epoch));
        }
    }

    public static RecordCipher getRecordCipher(TlsContext context, KeySet keySet, boolean isEncCipher) {
        return getRecordCipher(context, keySet, context.getChooser().getSelectedCipherSuite(), isEncCipher);
    }

    public static RecordNullCipher getNullCipher(TlsContext context, boolean isEncCipher) {
        int epoch =
            isEncCipher ? context.getRecordLayer().getNextWriteEpoch() : context.getRecordLayer().getNextReadEpoch();
        return new RecordNullCipher(context, new CipherState(context.getChooser().getSelectedProtocolVersion(),
            context.getChooser().getSelectedCipherSuite(), null, null, epoch));
    }

    private RecordCipherFactory() {
    }
}
