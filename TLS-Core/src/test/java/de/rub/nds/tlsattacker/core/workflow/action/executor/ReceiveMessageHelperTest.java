/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action.executor;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.IOException;
import org.junit.Assert;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

public class ReceiveMessageHelperTest {

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

    private void checkMessage(ProtocolMessage message, byte[] expectedMessage) {
        assertArrayEquals(expectedMessage, message.getCompleteResultingMessage().getOriginalValue());
    }

    private MessageActionResult receive(byte[]... records) {
        byte[] stream = ArrayConverter.concatenate(records);
        transportHandler.setFetchableByte(stream);
        return receiver.receiveMessages(context);
    }

    @Test
    public void testReceiveDTLSFragment() {
        MessageActionResult result = receive(DTLS.REC_SERVER_HELLO_F1);
        assertEquals(result.getMessageFragmentList().size(), 1);
        assertEquals(result.getMessageList().size(), 0);
        DtlsHandshakeMessageFragment fragment = (DtlsHandshakeMessageFragment) result.getMessageFragmentList().get(0);
        checkFragment(fragment, 1, 0, 75);
    }

    @Test
    public void testReceiveDTLSMessages() {
        MessageActionResult result = receive(DTLS.REC_HELLO_VERIFY_REQUEST, DTLS.REC_SERVER_HELLO_F1,
            DTLS.REC_SERVER_HELLO_F2, DTLS.REC_SERVER_HELLO_DONE);
        assertEquals(4, result.getMessageFragmentList().size());
        assertEquals(2, result.getMessageList().size());
        checkMessage(result.getMessageList().get(1), DTLS.MSG_SERVER_HELLO_ASSEMBLED);
        DtlsHandshakeMessageFragment fragment = (DtlsHandshakeMessageFragment) result.getMessageFragmentList().get(3);
        checkFragment(fragment, 4, 0, 0);
    }

    @Test
    public void testReceiveDTLSMessagesDisorderly() {
        MessageActionResult result = receive(DTLS.REC_HELLO_VERIFY_REQUEST, DTLS.REC_SERVER_HELLO_F1,
            DTLS.REC_SERVER_HELLO_DONE, DTLS.REC_SERVER_HELLO_F2);
        assertEquals(4, result.getMessageFragmentList().size());
        assertEquals(2, result.getMessageList().size());
        checkMessage(result.getMessageList().get(1), DTLS.MSG_SERVER_HELLO_ASSEMBLED);
        DtlsHandshakeMessageFragment fragment = (DtlsHandshakeMessageFragment) result.getMessageFragmentList().get(3);
        checkFragment(fragment, 4, 0, 0);
    }

    @Test
    public void testReceiveDTLSMessagesSeparatelyDisorderly() {
        context.setSelectedProtocolVersion(ProtocolVersion.DTLS12);
        MessageActionResult result = receive(DTLS.REC_HELLO_VERIFY_REQUEST);
        assertEquals(1, result.getMessageFragmentList().size());
        assertEquals(1, result.getMessageList().size());
        result = receive(DTLS.REC_SERVER_HELLO_F1);
        assertEquals(1, result.getMessageFragmentList().size());
        assertEquals(0, result.getMessageList().size());
        result = receive(DTLS.REC_SERVER_HELLO_DONE);
        assertEquals(1, result.getMessageFragmentList().size());
        assertEquals(0, result.getMessageList().size());
        result = receive(DTLS.REC_SERVER_HELLO_F2);
        assertEquals(1, result.getMessageFragmentList().size());
        assertEquals(1, result.getMessageList().size());
        checkMessage(result.getMessageList().get(0), DTLS.MSG_SERVER_HELLO_ASSEMBLED);
        Assert.assertArrayEquals(ArrayConverter.concatenate(DTLS.MSG_SERVER_HELLO_SINGLE_FRAGMENT),
            context.getDigest().getRawBytes());
    }

    /**
     * Tests behavior if multiple retransmissions of the same message are received.
     */
    @Test
    public void testReceiveDTLSMessagesManyRepeats() {
        context.setSelectedProtocolVersion(ProtocolVersion.DTLS12);
        MessageActionResult result = receive(DTLS.REC_SERVER_HELLO_F1, DTLS.REC_SERVER_HELLO_F2,
            DTLS.REC_SERVER_HELLO_F1, DTLS.REC_SERVER_HELLO_F2, DTLS.REC_SERVER_HELLO_F1, DTLS.REC_SERVER_HELLO_F2);
        assertEquals(6, result.getMessageFragmentList().size());
        // This is one message - 3 times the same but still one
        assertEquals(0, result.getMessageList().size());
    }

    static class DTLS {

        // DTLS 1.2 HELLO VERIFY REQEUST mseq 0, length 31, f. offset 0, f. length
        // 0
        private static final byte[] REC_HELLO_VERIFY_REQUEST = ArrayConverter.hexStringToByteArray(
            "16feff0000000000000000001f030000130000000000000013feff1031323334353637383930313233343536");

        private static final byte[] MSG_HELLO_VERIFY_REQUEST_SINGLE_FRAGMENT =
            ArrayConverter.hexStringToByteArray("030000130000000000000013feff1031323334353637383930313233343536");

        // what is expected when assembling the HELLO VERIFY REQEUST message
        private static final byte[] MSG_HELLO_VERIFY_REQUEST_ASSEMBLED =
            ArrayConverter.hexStringToByteArray("03000013feff1031323334353637383930313233343536");

        // DTLS 1.2 SERVER HELLO part 1: mseq 1, length 91, f. offset 0, f.
        // length 75
        private static final byte[] REC_SERVER_HELLO_F1 = ArrayConverter
            .hexStringToByteArray("16fefd0000000000000004005" + "70200005b000100000000004bfefd5c83e461a9320674e42d"
                + "4cb1e05191c7c416e1da6551e71e9a8b39cdbf3d393f20844"
                + "f60860755d38ef42247163793dad66e12e3ead668107e7837" + "96c24c48c28bc030000013001700");

        // DTLS 1.2 SERVER HELLO part 2: mseq 1, length 91, f. offset 75, f.
        // length 16
        private static final byte[] REC_SERVER_HELLO_F2 = ArrayConverter.hexStringToByteArray(
            "16fefd0000000000000005001c" + "0200005b000100004b00001000ff0100010000230000000b0" + "0020100");

        private static final byte[] MSG_SERVER_HELLO_SINGLE_FRAGMENT = ArrayConverter.hexStringToByteArray(
            "0200005B000100000000005BFEFD5C83E461A9320674E42D4CB1E05191C7C416E1DA6551E71E9A8B39CDBF3D393F20844F60860755D38EF42247163793DAD66E12E3EAD668107E783796C24C48C28BC03000001300170000FF0100010000230000000B00020100");

        // what is expected when assembling the SERVER_HELLO message
        private static final byte[] MSG_SERVER_HELLO_ASSEMBLED = ArrayConverter.hexStringToByteArray(
            "0200005bfefd5c83e461a9320674" + "e42d4cb1e05191c7c416e1da6551e71e9a8b39cdbf3d393f20844f60860755d38ef"
                + "42247163793dad66e12e3ead668107e783796c24c48c28bc03000001300170000ff"
                + "0100010000230000000b00020100");

        // DTLS 1.2 SERVER HELLO DONE mseq 4, length 12, f. offset 0, f. length
        // 0
        private static final byte[] REC_SERVER_HELLO_DONE =
            ArrayConverter.hexStringToByteArray("16fefd0000000000000017000c0e0000000004000000000000");

        private static final byte[] MSG_SERVER_HELLO_DONE_SINGLE_FRAGMENT =
            ArrayConverter.hexStringToByteArray("0e0000000004000000000000");

        // what is expected when assembling the SERVER HELLO DONE message
        private static final byte[] MSG_SERVER_HELLO_DONE_ASSEMBLED = ArrayConverter.hexStringToByteArray("0E000000");

    }

}
