/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record.handler;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class RecordHandlerTest {

    private RecordHandler handler;
    private TlsContext tlsContext;
    private Record record;

    @BeforeEach
    public void setUp() {
        State state = new State();
        Context context = state.getContext();
        tlsContext = context.getTlsContext();
        handler = new RecordHandler(tlsContext);
        record = new Record();
    }

    @Test
    public void testAdjustContextWithTLS12() {
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());

        handler.adjustContext(record);

        assertEquals(ProtocolVersion.TLS12, tlsContext.getLastRecordVersion());
    }

    @Test
    public void testAdjustContextWithTLS13() {
        record.setProtocolVersion(ProtocolVersion.TLS13.getValue());

        handler.adjustContext(record);

        assertEquals(ProtocolVersion.TLS13, tlsContext.getLastRecordVersion());
    }

    @Test
    public void testRecordGetHandlerReturnsRecordHandler() {
        State state = new State();
        Context context = state.getContext();

        var handler = record.getHandler(context);

        assertEquals(RecordHandler.class, handler.getClass());
    }
}
