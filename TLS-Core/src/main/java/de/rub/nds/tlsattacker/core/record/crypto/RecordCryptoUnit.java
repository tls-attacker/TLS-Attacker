/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.crypto;

import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;

public abstract class RecordCryptoUnit {

    protected RecordCipher recordCipher;

    public RecordCryptoUnit(RecordCipher recordCipher) {
        this.recordCipher = recordCipher;
    }

    public RecordCipher getRecordCipher() {
        return recordCipher;
    }

    public void setRecordCipher(RecordCipher recordCipher) {
        this.recordCipher = recordCipher;
    }

    
}
