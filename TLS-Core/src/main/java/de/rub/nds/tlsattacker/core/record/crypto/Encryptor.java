/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.record.crypto;

import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class Encryptor extends RecordCryptoUnit {

    private static final Logger LOGGER = LogManager.getLogger();

    public Encryptor(RecordCipher cipher) {
        super(cipher);
    }

    void encrypt(AbstractRecord object) throws CryptoException {
        if (object instanceof BlobRecord) {
            encrypt((BlobRecord) object);
        } else if (object instanceof Record) {
            encrypt((Record) object);
        } else {
            throw new UnsupportedOperationException("Record type unknown.");
        }
    }

    public abstract void encrypt(Record object);

    public abstract void encrypt(BlobRecord object);
}
