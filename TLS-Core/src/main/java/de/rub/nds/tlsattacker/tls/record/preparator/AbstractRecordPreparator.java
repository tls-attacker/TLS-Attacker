/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.record.preparator;

import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.tls.record.AbstractRecord;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;

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
    }

    protected void prepareConentMessageType(ProtocolMessageType tpye) {
        getObject().setContentMessageType(type);
        LOGGER.debug("ContentMessageType: " + ArrayConverter.bytesToHexString(tpye.getArrayValue()));
    }
}
