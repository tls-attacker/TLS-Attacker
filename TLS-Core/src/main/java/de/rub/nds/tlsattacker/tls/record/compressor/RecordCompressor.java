/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.record.compressor;

import de.rub.nds.tlsattacker.tls.record.AbstractRecord;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public abstract class RecordCompressor extends Compressor<AbstractRecord> {

    @Override
    public void compress(AbstractRecord record) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

}
