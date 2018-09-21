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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordCipherFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    public static RecordCipher getRecordCipher(TlsContext context, KeySet keySet, CipherSuite cipherSuite) {
        try {
            if (context.getChooser().getSelectedCipherSuite() == null || !cipherSuite.isImplemented()) {
                LOGGER.warn("Cipher " + cipherSuite.name() + " not implemented. Using Null Cipher instead");
                return new RecordNullCipher(context);
            } else {
                CipherType type = AlgorithmResolver.getCipherType(cipherSuite);
                switch (type) {
                    case AEAD:
                        return new RecordAEADCipher(context, keySet);
                    case BLOCK:
                        return new RecordBlockCipher(context, keySet);
                    case STREAM:
                        return new RecordStreamCipher(context, keySet);
                }
                LOGGER.warn("UnknownCipherType:" + type.name());
                return new RecordNullCipher(context);
            }
        } catch (Exception E) {
            LOGGER.debug("Could not create RecordCipher from the current Context! Creating null Cipher", E);
            return new RecordNullCipher(context);
        }
    }

    public static RecordCipher getRecordCipher(TlsContext context, KeySet keySet) {
        return getRecordCipher(context, keySet, context.getChooser().getSelectedCipherSuite());
    }

    private RecordCipherFactory() {
    }
}
