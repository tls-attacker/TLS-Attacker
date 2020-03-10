/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
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

    public RecordNullCipher(TlsContext context) {
        super(context, null);
    }

    @Override
    public boolean isUsingPadding() {
        return false;
    }

    @Override
    public boolean isUsingMac() {
        return false;
    }

    @Override
    public boolean isUsingTags() {
        return false;
    }

    @Override
    public void encrypt(Record record) {

        LOGGER.debug("Encrypting Record: (null cipher)");
        record.prepareComputations();
        byte[] cleanBytes = record.getCleanProtocolMessageBytes().getValue();
        record.setProtocolMessageBytes(cleanBytes);
    }

    @Override
    public void decrypt(Record record) {
        LOGGER.debug("Decrypting Record: (null cipher)");
        record.prepareComputations();
        byte[] protocolMessageBytes = record.getProtocolMessageBytes().getValue();
        record.setCleanProtocolMessageBytes(protocolMessageBytes);
    }

    @Override
    public void encrypt(BlobRecord br) throws CryptoException {
        LOGGER.debug("Encrypting BlobRecord: (null cipher)");
        br.setProtocolMessageBytes(br.getCleanProtocolMessageBytes().getValue());
    }

    @Override
    public void decrypt(BlobRecord br) throws CryptoException {
        LOGGER.debug("Derypting BlobRecord: (null cipher)");
        br.setProtocolMessageBytes(br.getCleanProtocolMessageBytes().getValue());
    }

}
