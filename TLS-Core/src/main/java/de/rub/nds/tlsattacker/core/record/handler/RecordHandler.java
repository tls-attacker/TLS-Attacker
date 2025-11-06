/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record.handler;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.record.Record;

/** Handler for processing Record objects after parsing. */
public class RecordHandler extends Handler<Record> {

    private final TlsContext tlsContext;

    public RecordHandler(TlsContext tlsContext) {
        this.tlsContext = tlsContext;
    }

    @Override
    public void adjustContext(Record record) {
        ProtocolVersion protocolVersion =
                ProtocolVersion.getProtocolVersion(record.getProtocolVersion().getValue());
        tlsContext.setLastRecordVersion(protocolVersion);
    }
}
