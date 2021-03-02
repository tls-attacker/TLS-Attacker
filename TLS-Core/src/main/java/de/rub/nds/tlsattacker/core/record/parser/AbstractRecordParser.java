/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsattacker.core.record.parser;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.Parser;

/**
 * @param <AbstractRecordT>
 * The Abstract record that should be parsed
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
