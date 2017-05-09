/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.preparator;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 * @param <T>
 */
public abstract class AbstractRecordPreparator<T extends AbstractRecord> extends Preparator<T> {

    protected ProtocolMessageType type;

    public AbstractRecordPreparator(TlsContext context, T object, ProtocolMessageType type) {
        super(context, object);
        this.type = type;
        object.setContentMessageType(type);
    }
}
