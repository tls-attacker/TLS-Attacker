/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.record.encryptor;

import de.rub.nds.tlsattacker.tls.record.BlobRecord;
import de.rub.nds.tlsattacker.tls.record.cipher.RecordCipher;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class BlobEncryptor extends Encryptor<BlobRecord> {

    public BlobEncryptor(RecordCipher cipher) {
        super(cipher);
    }

    @Override
    public void encrypt(BlobRecord object) {

    }

}
