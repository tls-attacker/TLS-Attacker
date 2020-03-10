/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.crypto;

import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordEncryptor extends Encryptor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final TlsContext context;

    public RecordEncryptor(RecordCipher recordCipher, TlsContext context) {
        super(recordCipher);
        this.context = context;
    }

    @Override
    public void encrypt(BlobRecord record) throws CryptoException {
        LOGGER.debug("Encrypting BlobRecord");
        recordCipher.encrypt(record);
    }

    @Override
    public void encrypt(Record record) throws CryptoException {

        LOGGER.debug("Encrypting Record:");
        recordCipher.encrypt(record);
        context.increaseWriteSequenceNumber();
    }
}
