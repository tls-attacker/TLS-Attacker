/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.layer;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import java.util.LinkedList;
import java.util.List;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class RecordLayerTest {

    RecordLayer recordHandler;

    @Before
    public void setUp() {

        Config config = Config.createConfig();
        config.setRecordLayerType(RecordLayerType.RECORD);
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace = factory.createWorkflowTrace(WorkflowTraceType.HANDSHAKE, RunningModeType.CLIENT);
        State state = new State(config, trace);
        TlsContext context = state.getTlsContext();
        context.setRecordLayer(new TlsRecordLayer(context));
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        recordHandler = context.getRecordLayer();
    }

    /**
     * Test of prepare method, of class TlsRecordLayer.
     */
    @Test
    public void testWrapData() {
        byte[] data = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
        byte[] result;
        List<AbstractRecord> records = new LinkedList<>();
        records.add(new Record());
        result = recordHandler.prepareRecords(data, ProtocolMessageType.HANDSHAKE, records);

        byte[] expectedResult = { 22, 3, 3, 0, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

        assertEquals(records.size(), 1);
        assertArrayEquals(expectedResult, result);

        Record preconfiguredRecord = new Record();
        preconfiguredRecord.setMaxRecordLengthConfig(2);
        records.clear();
        records.add(preconfiguredRecord);

        result = recordHandler.prepareRecords(data, ProtocolMessageType.HANDSHAKE, records);
        assertEquals(1, records.size());
        assertEquals(7, result.length);

        records.clear();
        preconfiguredRecord = new Record();
        preconfiguredRecord.setMaxRecordLengthConfig(2);
        records.add(preconfiguredRecord);
        records.add(preconfiguredRecord);

        result = recordHandler.prepareRecords(data, ProtocolMessageType.HANDSHAKE, records);
        assertEquals(2, records.size());
        assertEquals(14, result.length);

        records = recordHandler.parseRecords(result);
        assertEquals(2, records.size());
    }
}
