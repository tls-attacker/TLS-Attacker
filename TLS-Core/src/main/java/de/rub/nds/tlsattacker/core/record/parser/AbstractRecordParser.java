/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.record.parser;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.parser.Parser;

/**
 * @param <AbstractRecordT>
 *                          The Abstract record that should be parsed
 */
public abstract class AbstractRecordParser<AbstractRecordT> extends Parser<AbstractRecordT> {

    protected final ProtocolVersion version;

    public AbstractRecordParser(int startposition, byte[] array, ProtocolVersion version) {
        super(startposition, array);
        this.version = version;
    }

    public ProtocolVersion getVersion() {
        return version;
    }
}
