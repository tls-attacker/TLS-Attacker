/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.record;

import de.rub.nds.tlsattacker.tls.record.RecordHandler;
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.record.Record;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowConfigurationFactory;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class RecordHandlerTest {

    RecordHandler recordHandler;

    public RecordHandlerTest() {
	Security.addProvider(new BouncyCastleProvider());
	ClientCommandConfig config = new ClientCommandConfig();
	WorkflowConfigurationFactory factory = WorkflowConfigurationFactory.createInstance(config);
	TlsContext context = factory.createHandshakeTlsContext(ConnectionEnd.CLIENT);
	context.setRecordHandler(new RecordHandler(context));
	recordHandler = context.getRecordHandler();
    }

    /**
     * Test of wrapData method, of class RecordHandler.
     */
    @Test
    public void testWrapData() {
	byte[] data = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
	byte[] result;
	List<Record> records = new LinkedList<>();
	records.add(new Record());
	result = recordHandler.wrapData(data, ProtocolMessageType.HANDSHAKE, records);

	byte[] expectedResult = { 22, 3, 3, 0, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

	assertEquals(records.size(), 1);
	assertArrayEquals(expectedResult, result);

	Record preconfiguredRecord = new Record();
	preconfiguredRecord.setMaxRecordLengthConfig(2);
	records.clear();
	records.add(preconfiguredRecord);

	result = recordHandler.wrapData(data, ProtocolMessageType.HANDSHAKE, records);
	assertEquals(2, records.size());
	assertEquals(20, result.length);

	records.clear();
	preconfiguredRecord = new Record();
	preconfiguredRecord.setMaxRecordLengthConfig(2);
	records.add(preconfiguredRecord);
	records.add(preconfiguredRecord);

	result = recordHandler.wrapData(data, ProtocolMessageType.HANDSHAKE, records);
	assertEquals(3, records.size());
	assertEquals(25, result.length);

	records = recordHandler.parseRecords(result);
	assertEquals(3, records.size());
    }
}
