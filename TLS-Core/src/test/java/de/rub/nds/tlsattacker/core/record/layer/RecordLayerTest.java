/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.layer;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import java.util.LinkedList;
import java.util.List;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class RecordLayerTest {

    RecordLayer recordHandler;

    @Before
    public void setUp() {
        TlsConfig config = TlsConfig.createConfig();
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace = factory.createHandshakeWorkflow();
        config.setWorkflowTrace(trace);
        config.setRecordLayerType(RecordLayerType.RECORD);
        TlsContext context = new TlsContext(config);
        context.setRecordLayer(new TlsRecordLayer(context));
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
