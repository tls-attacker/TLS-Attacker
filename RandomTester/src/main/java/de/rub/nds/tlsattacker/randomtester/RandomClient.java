/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
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
package de.rub.nds.tlsattacker.randomtester;

import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.protocol.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.handlers.ClientHelloHandler;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.record.handlers.RecordHandler;
import de.rub.nds.tlsattacker.tls.record.messages.Record;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.transport.SimpleTransportHandler;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class RandomClient {

    private static Logger LOGGER = LogManager.getLogger(RandomClient.class);

    private static final int RANDOM_END_POSITION = 43;

    private static final int RANDOM_START_POSITION = 15;

    private static byte[] request;

    private List<byte[]> responseRandoms;

    private final int threads;

    private final ClientCommandConfig config;

    private final String address;

    private final int port;

    public RandomClient(ClientCommandConfig config, int threads) {
	responseRandoms = new LinkedList<>();
	this.threads = threads;
	this.config = config;
	this.address = config.getConnect().split(":")[0];
	this.port = Integer.parseInt(config.getConnect().split(":")[1]);
    }

    public static void initializeRequest() {
	TlsContext context = new TlsContext();
	ClientHelloHandler handler = new ClientHelloHandler(context);
	handler.initializeProtocolMessage();
	ClientHelloMessage cm = (ClientHelloMessage) handler.getProtocolMessage();
	ClientCommandConfig ccc = new ClientCommandConfig();
	cm.setSupportedCipherSuites(ccc.getCipherSuites());
	cm.setSupportedCompressionMethods(ccc.getCompressionMethods());
	byte[] ch = handler.prepareMessageAction();
	LOGGER.debug("Created the following client hello message: {}", ArrayConverter.bytesToHexString(ch));
        context.setRecordHandler(new RecordHandler(context));
	RecordHandler rh = context.getRecordHandler();
	List<Record> records = new LinkedList<>();
	records.add(new Record());
	byte[] result = rh.wrapData(ch, ProtocolMessageType.HANDSHAKE, records);
	LOGGER.debug("The resulting record is: {}", ArrayConverter.bytesToHexString(result));
	request = result;
    }

    public void sendRequests() {
	RequestSender[] senders = new RequestSender[threads];
	for (int i = 0; i < threads; i++) {
	    senders[i] = new RequestSender();
	}

	for (int i = 0; i < threads; i++) {
	    senders[i].start();
	}

	boolean readyToProceed = false;
	while (!readyToProceed) {
	    readyToProceed = true;
	    for (int i = 0; i < threads; i++) {
		if (!senders[i].executed) {
		    readyToProceed = false;
		}
	    }
	}

	for (int i = 0; i < threads; i++) {
	    byte[] response = senders[i].getResponse();
	    if (response != null && response.length != 0) {
		responseRandoms.add(Arrays.copyOfRange(response, 15, 43));
		LOGGER.debug(i
			+ ":"
			+ ArrayConverter.bytesToHexString(Arrays.copyOfRange(response, RANDOM_START_POSITION,
				RANDOM_END_POSITION)));
	    }
	}

	this.searchForMaxOverlap();
    }

    public void searchForMaxOverlap() {
	int maxOverlap = 1;
	for (int i = 0; i < responseRandoms.size(); i++) {
	    for (int j = i + 1; j < responseRandoms.size(); j++) {
		byte[] r1 = responseRandoms.get(i);
		byte[] r2 = responseRandoms.get(j);
		int ocurrent = getOverlap(maxOverlap, r1, r2);
		if (ocurrent > maxOverlap) {
		    maxOverlap = ocurrent;
		    LOGGER.debug("Found overlap of {} bytes between randoms {} and {}", ocurrent, i, j);
		}
	    }
	}
    }

    public int getOverlap(int maxOverlap, byte[] r1, byte[] r2) {
	int overlap = 0;
	for (int i = 0; i < r1.length; i++) {
	    for (int j = i; j < r2.length; j++) {
		if (r1[i] == r2[j]) {
		    int ocurrent = getOverlap(r1, i, r2, j);
		    if (ocurrent > overlap) {
			overlap = ocurrent;
			if (ocurrent > maxOverlap) {
			    LOGGER.debug("The new max overlap found on position r1[{}], r2[{}]", i, j);
			}
		    }
		}
	    }
	}
	return overlap;
    }

    private int getOverlap(byte[] r1, int p1, byte[] r2, int p2) {
	int overlap = 0;
	while (p1 < r1.length && p2 < r2.length) {
	    if (r1[p1] == r2[p2]) {
		overlap++;
		p1++;
		p2++;
	    } else {
		return overlap;
	    }
	}
	return overlap;
    }

    public class RequestSender extends Thread {

	private byte[] response;

	private boolean executed;

	@Override
	public void run() {
	    SimpleTransportHandler th = new SimpleTransportHandler();
	    th.setMaxResponseWait(10000);
	    try {
		th.initialize(address, port);
		th.sendData(request);
		this.response = th.fetchData();
		executed = true;
		th.closeConnection();
	    } catch (IOException ex) {
		LOGGER.error(ex);
	    }
	}

	public byte[] getResponse() {
	    return response;
	}

	public boolean isExecuted() {
	    return executed;
	}
    }

}