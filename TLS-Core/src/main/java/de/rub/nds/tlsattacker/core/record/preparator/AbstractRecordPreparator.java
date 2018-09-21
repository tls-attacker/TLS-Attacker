/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @param <T>
 *            The AbstractRecord that should be prepared
 */
public abstract class AbstractRecordPreparator<T extends AbstractRecord> extends Preparator<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected ProtocolMessageType type;

    public AbstractRecordPreparator(Chooser chooser, T object, ProtocolMessageType type) {
        super(chooser, object);
        this.type = type;
    }

    protected void prepareConentMessageType(ProtocolMessageType tpye) {
        getObject().setContentMessageType(type);
        LOGGER.debug("ContentMessageType: " + ArrayConverter.bytesToHexString(tpye.getArrayValue()));
    }
}
