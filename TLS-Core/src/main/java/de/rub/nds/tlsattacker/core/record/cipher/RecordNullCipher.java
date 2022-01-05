/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.record.cipher;

import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordNullCipher extends RecordCipher {

    private static final Logger LOGGER = LogManager.getLogger();

    public RecordNullCipher(TlsContext context, CipherState state) {
        super(context, state);
    }

    @Override
    public void encrypt(Record record) throws CryptoException {

        LOGGER.debug("Encrypting Record: (null cipher)");
        record.prepareComputations();
        byte[] cleanBytes = record.getCleanProtocolMessageBytes().getValue();
        record.setProtocolMessageBytes(cleanBytes);
    }

    @Override
    public void encrypt(BlobRecord br) throws CryptoException {
        LOGGER.debug("Encrypting BlobRecord: (null cipher)");
        br.setProtocolMessageBytes(br.getCleanProtocolMessageBytes().getValue());
    }

    @Override
    public void decrypt(Record record) throws CryptoException {
        LOGGER.debug("Decrypting Record: (null cipher)");
        record.prepareComputations();
        byte[] protocolMessageBytes = record.getProtocolMessageBytes().getValue();
        record.setCleanProtocolMessageBytes(protocolMessageBytes);
    }

    @Override
    public void decrypt(BlobRecord br) throws CryptoException {
        LOGGER.debug("Decrypting BlobRecord: (null cipher)");
        br.setCleanProtocolMessageBytes(br.getProtocolMessageBytes().getValue());
    }

}
