/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.record.crypto;

import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class Decryptor extends RecordCryptoUnit {

    private static final Logger LOGGER = LogManager.getLogger();

    public Decryptor(RecordCipher cipher) {
        super(cipher);

    }

    public void decrypt(AbstractRecord object) {
        if (object instanceof BlobRecord) {
            decrypt((BlobRecord) object);
        } else if (object instanceof Record) {
            decrypt((Record) object);
        } else {
            throw new UnsupportedOperationException("Record type unknown.");
        }
    }

    public abstract void decrypt(Record object);

    public abstract void decrypt(BlobRecord object);
}
