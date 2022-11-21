/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.record.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.Preparator;
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

    public abstract void encrypt();

    protected void prepareContentMessageType(ProtocolMessageType type) {
        getObject().setContentMessageType(this.type);
        LOGGER.debug("ContentMessageType: " + ArrayConverter.bytesToHexString(type.getArrayValue()));
    }
}
