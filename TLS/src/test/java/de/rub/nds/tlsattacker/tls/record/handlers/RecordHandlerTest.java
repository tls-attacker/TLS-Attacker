/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.tls.record.handlers;

import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.protocol.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.record.messages.Record;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.factory.WorkflowConfigurationFactory;
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
	TlsContext context = factory.createHandshakeTlsContext();
	recordHandler = RecordHandler.createInstance(context);
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
