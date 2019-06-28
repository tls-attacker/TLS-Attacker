/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action.executor;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.IOException;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

public class ReceiveMessageHelperTest {

    static class DTLS {
        // DTLS 1.2 Server Hello part 1: mseq 1, length 91, f. offset 0, f.
        // length 75
        private static final String REC_SERVER_HELLO_F1 = "16fefd0000000000000004005"
                + "70200005b000100000000004bfefd5c83e461a9320674e42d"
                + "4cb1e05191c7c416e1da6551e71e9a8b39cdbf3d393f20844"
                + "f60860755d38ef42247163793dad66e12e3ead668107e7837" + "96c24c48c28bc030000013001700";

        // DTLS 1.2 Server Hello part 2: mseq 1, length 91, f. offset 75, f.
        // length 16
        private static final String REC_SERVER_HELLO_F2 = "16fefd0000000000000005001c"
                + "0200005b000100004b00001000ff0100010000230000000b0" + "0020100";

        // what is expected when assembling the SERVER_HELLO message
        private static final String MSG_SERVER_HELLO_ASSEMBLED = "0200005bfefd5c83e461a9320674"
                + "e42d4cb1e05191c7c416e1da6551e71e9a8b39cdbf3d393f20844f60860755d38ef"
                + "42247163793dad66e12e3ead668107e783796c24c48c28bc03000001300170000ff"
                + "0100010000230000000b00020100";

        // DTLS 1.2 Server Hello Done mseq 4, length 12, f. offset 0, f. length
        // 0
        private static final String REC_SERVER_HELLO_DONE = "16fefd000000000000001700" + "0c0e0000000004000000000000";
    }

    private TlsContext context;
    private FakeTransportHandler transportHandler;
    private ReceiveMessageHelper receiver;

    @Before
    public void setUp() throws IOException {
        context = new TlsContext();
        context.getConfig().setDefaultSelectedProtocolVersion(ProtocolVersion.DTLS12);
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

    private MessageActionResult receive(String... hexRecords) {
        StringBuilder builder = new StringBuilder();
        for (String hex : hexRecords)
            builder.append(hex);
        transportHandler.setFetchableByte(ArrayConverter.hexStringToByteArray(builder.toString()));
        return receiver.receiveMessages(context);
    }

    @Test
    public void testReceiveDTLSFragment() {
        MessageActionResult result = receive(DTLS.REC_SERVER_HELLO_F1);
        assertEquals(result.getMessageFragmentList().size(), 1);
        DtlsHandshakeMessageFragment fragment = (DtlsHandshakeMessageFragment) result.getMessageFragmentList().get(0);
        checkFragment(fragment, 1, 0, 75);
    }

    @Test
    public void testReceiveDTLSMessages() {
        context.setDtlsNextReceiveSequenceNumber(1);
        MessageActionResult result = receive(DTLS.REC_SERVER_HELLO_F1, DTLS.REC_SERVER_HELLO_F2,
                DTLS.REC_SERVER_HELLO_DONE);
        assertEquals(3, result.getMessageFragmentList().size());
        assertEquals(2, result.getMessageList().size());
        checkMessage(result.getMessageList().get(0), DTLS.MSG_SERVER_HELLO_ASSEMBLED);
    }

    @Test
    public void testReceiveDTLSMessagesDisorderly() {
        context.setDtlsNextReceiveSequenceNumber(1);
        MessageActionResult result = receive(DTLS.REC_SERVER_HELLO_F1, DTLS.REC_SERVER_HELLO_DONE,
                DTLS.REC_SERVER_HELLO_F2);
        assertEquals(3, result.getMessageFragmentList().size());
        assertEquals(2, result.getMessageList().size());
        checkMessage(result.getMessageList().get(1), DTLS.MSG_SERVER_HELLO_ASSEMBLED);
    }

    @Test
    public void testReceiveDTLSMessagesSeparatelyDisorderly() {
        context.setDtlsNextReceiveSequenceNumber(0);
        context.setSelectedProtocolVersion(ProtocolVersion.DTLS12);
        MessageActionResult result = receive(DTLS.REC_SERVER_HELLO_F1);
        assertEquals(1, result.getMessageFragmentList().size());
        assertEquals(0, result.getMessageList().size());
        result = receive(DTLS.REC_SERVER_HELLO_DONE);
        assertEquals(1, result.getMessageFragmentList().size());
        assertEquals(1, result.getMessageList().size());
        result = receive(DTLS.REC_SERVER_HELLO_F2);
        assertEquals(1, result.getMessageList().size());
        checkMessage(result.getMessageList().get(0), DTLS.MSG_SERVER_HELLO_ASSEMBLED);
        // the digest shouldn't have been updated since the message is received
        // out-of-order
        assertEquals(0, context.getDigest().getRawBytes().length);
    }

    /**
     * Tests behavior if multiple retransmissions of the same message are
     * received.
     */
    @Test
    public void testReceiveDTLSMessagesManyRepeats() {
        context.setDtlsNextReceiveSequenceNumber(0);
        context.setSelectedProtocolVersion(ProtocolVersion.DTLS12);
        MessageActionResult result = receive(DTLS.REC_SERVER_HELLO_F1, DTLS.REC_SERVER_HELLO_F2,
                DTLS.REC_SERVER_HELLO_F1, DTLS.REC_SERVER_HELLO_F2, DTLS.REC_SERVER_HELLO_F1, DTLS.REC_SERVER_HELLO_F2);
        assertEquals(6, result.getMessageFragmentList().size());
        assertEquals(3, result.getMessageList().size());
    }

    /**
     * Same test, but now with ignore disorderly messages option
     */
    @Test
    public void testReceiveDTLSMessagesManyRepeatsIgnoreDisorderly() {
        context.setDtlsNextReceiveSequenceNumber(1);
        context.getConfig().setDtlsExcludeOutOfOrder(true);
        MessageActionResult result = receive(DTLS.REC_SERVER_HELLO_F1, DTLS.REC_SERVER_HELLO_F2,
                DTLS.REC_SERVER_HELLO_F1, DTLS.REC_SERVER_HELLO_F2, DTLS.REC_SERVER_HELLO_F1, DTLS.REC_SERVER_HELLO_F2);
        assertEquals(6, result.getMessageFragmentList().size());
        assertEquals(1, result.getMessageList().size());
    }

}
