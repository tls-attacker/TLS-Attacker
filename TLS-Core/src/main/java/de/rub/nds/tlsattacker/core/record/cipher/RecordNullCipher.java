/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record.cipher;

import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.record.Record;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordNullCipher extends RecordCipher {

    private static final Logger LOGGER = LogManager.getLogger();

    public RecordNullCipher(TlsContext tlsContext, CipherState state) {
        super(tlsContext, state);
    }

    @Override
    public void encrypt(Record record) throws CryptoException {

        LOGGER.debug("Encrypting Record: (null cipher)");
        record.prepareComputations();
        byte[] cleanBytes = record.getCleanProtocolMessageBytes().getValue();
        record.setProtocolMessageBytes(cleanBytes);
    }

    @Override
    public void decrypt(Record record) throws CryptoException {
        LOGGER.debug("Decrypting Record: (null cipher)");
        record.prepareComputations();
        byte[] protocolMessageBytes = record.getProtocolMessageBytes().getValue();
        record.setCleanProtocolMessageBytes(protocolMessageBytes);
    }
}
