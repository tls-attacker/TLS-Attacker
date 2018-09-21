/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.crypto;

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

    void encrypt(AbstractRecord object) {
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
