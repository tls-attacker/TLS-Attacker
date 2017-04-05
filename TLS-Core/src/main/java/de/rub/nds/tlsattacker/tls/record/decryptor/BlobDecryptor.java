/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.record.decryptor;

import de.rub.nds.tlsattacker.tls.record.BlobRecord;
import de.rub.nds.tlsattacker.tls.record.cipher.RecordCipher;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class BlobDecryptor extends Decryptor<BlobRecord> {

    public BlobDecryptor(RecordCipher cipher) {
        super(cipher);
    }

    @Override
    public void decrypt(BlobRecord record) {
        byte[] decrypted = recordCipher.decrypt(record.getProtocolMessageBytes().getValue());
        record.setCleanProtocolMessageBytes(decrypted);
    }

}
