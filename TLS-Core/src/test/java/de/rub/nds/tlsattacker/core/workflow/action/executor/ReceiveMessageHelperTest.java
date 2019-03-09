package de.rub.nds.tlsattacker.core.workflow.action.executor;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.converters.ByteArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.HeartbeatExtensionMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.stream.StreamTransportHandler;

public class ReceiveMessageHelperTest {
	

	// DTLS 1.2 Server Hello part 1: mseq 1, length 91, f. offset 0, f. length 75 
	private static final String REC_SERVER_HELLO_F1 = "16fefd0000000000000004005"
			+ "70200005b000100000000004bfefd5c83e461a9320674e42d"
			+ "4cb1e05191c7c416e1da6551e71e9a8b39cdbf3d393f20844"
			+ "f60860755d38ef42247163793dad66e12e3ead668107e7837"
			+ "96c24c48c28bc030000013001700";
	
	// DTLS 1.2  Server Hello part 2: mseq 1, length 91, f. offset 75, f. length 16 
	private static final String REC_SERVER_HELLO_F2 = "16fefd0000000000000005001c"
			+ "0200005b000100004b00001000ff0100010000230000000b0"
			+ "0020100";
	
	private static final String MSG_SERVER_HELLO_ASSEMBLED = "0200005bfefd5c83e461a9320674"
			+ "e42d4cb1e05191c7c416e1da6551e71e9a8b39cdbf3d393f20844f60860755d38ef"
			+ "42247163793dad66e12e3ead668107e783796c24c48c28bc03000001300170000ff"
			+ "0100010000230000000b00020100";
	
	// DTLS 1.2 Server Hello Done mseq 4, length 12, f. offset 0, f. length 0
	private static final String REC_SERVER_HELLO_DONE = "16fefd000000000000001700"
			+ "0c0e0000000004000000000000";
	

	
    private TlsContext context;
	private FakeTransportHandler transportHandler;
	private ReceiveMessageHelper receiver;
	
	
	@Before
    public void setUp() throws IOException {
        context = new TlsContext();
        context.setRecordLayer(new TlsRecordLayer(context));
        transportHandler = new FakeTransportHandler(ConnectionEndType.CLIENT);
        context.setTransportHandler(transportHandler);
        receiver = new ReceiveMessageHelper();
    }
	
	private void checkFragment(DtlsHandshakeMessageFragment fragment, int msgSeq, int fragOffset, int fragLength) {
		assertEquals(msgSeq, fragment.getMessageSeq().getValue().intValue());
		assertEquals(fragOffset, fragment.getFragmentOffset().getValue().intValue());
		assertEquals(fragLength, fragment.getFragmentLength().getValue().intValue());
	}
	
	private void checkMessage(ProtocolMessage msg, String expectedString) {
		String actualHex = ArrayConverter.bytesToHexString(msg.getCompleteResultingMessage().getOriginalValue());
		// we eliminate formatting as a factor
		String expectedHex = ArrayConverter.bytesToHexString(ArrayConverter.hexStringToByteArray(expectedString));
		assertEquals(expectedHex, actualHex);
		
	}
	
	private MessageActionResult receive(String ...hexRecords) {
		StringBuilder builder = new StringBuilder();
		for (String hex : hexRecords) 
			builder.append(hex);
		transportHandler.setFetchableByte(ArrayConverter.hexStringToByteArray(builder.toString()));
		return receiver.receiveMessages(context);
	}
	
	@Test
	public void testReceiveDTLSFragment() {
		context.setSelectedProtocolVersion(ProtocolVersion.DTLS12);
		MessageActionResult result = receive(REC_SERVER_HELLO_F1);
		assertEquals(result.getMessageFragmentList().size(), 1);
		DtlsHandshakeMessageFragment fragment = (DtlsHandshakeMessageFragment)result.getMessageFragmentList().get(0);
		checkFragment(fragment, 1, 0, 75);
	}
	
	@Test
	public void testReceiveDTLSMessages() {
		context.setSelectedProtocolVersion(ProtocolVersion.DTLS12);
		MessageActionResult result = receive(REC_SERVER_HELLO_F1, REC_SERVER_HELLO_F2, REC_SERVER_HELLO_DONE);
		assertEquals(3, result.getMessageFragmentList().size());
		assertEquals(2, result.getMessageList().size());
		checkMessage(result.getMessageList().get(0), MSG_SERVER_HELLO_ASSEMBLED);
	}
	
	@Test
	public void testReceiveDTLSMessageDisorderly() {
		context.setSelectedProtocolVersion(ProtocolVersion.DTLS12);
		MessageActionResult result = receive(REC_SERVER_HELLO_F1, REC_SERVER_HELLO_DONE, REC_SERVER_HELLO_F2);
		assertEquals(3, result.getMessageFragmentList().size());
		assertEquals(2, result.getMessageList().size());
		checkMessage(result.getMessageList().get(0), MSG_SERVER_HELLO_ASSEMBLED);
	}
	
}
