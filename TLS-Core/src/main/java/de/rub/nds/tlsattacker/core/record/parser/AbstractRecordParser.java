/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.parser;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.parser.Parser;

/**
 * @param <AbstractRecord>
 *            The Abstract record that should be parsed
 */
public abstract class AbstractRecordParser<AbstractRecord> extends Parser<AbstractRecord> {

    protected final ProtocolVersion version;

    public AbstractRecordParser(int startposition, byte[] array, ProtocolVersion version) {
        super(startposition, array);
        this.version = version;
    }

    public ProtocolVersion getVersion() {
        return version;
    }
}
