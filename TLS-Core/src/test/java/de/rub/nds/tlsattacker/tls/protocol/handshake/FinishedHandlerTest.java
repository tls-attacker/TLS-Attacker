/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake;

import de.rub.nds.tlsattacker.tls.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.exceptions.InvalidMessageTypeException;
import de.rub.nds.tlsattacker.tls.exceptions.NoCiphersuiteSelectedException;
import de.rub.nds.tlsattacker.tls.protocol.handler.FinishedHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Before;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class FinishedHandlerTest {

    private FinishedHandler finishedHandler;
    private FinishedMessage finishedMessage;
    private TlsContext context;

    public FinishedHandlerTest() {
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        finishedHandler = new FinishedHandler(context);
        finishedMessage = new FinishedMessage(context.getConfig());
    }

//    /**
//     * Test of prepareMessageAction method, of class FinishedHandler.
//     */
//    @Test
//    public void testPrepareMessageActionClient() {
//        finishedHandler.setProtocolMessage(finishedMessage);
//        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CCM);
//        finishedHandler.prepareMessageAction();
//        assertTrue(finishedMessage.getHandshakeMessageType() == HandshakeMessageType.FINISHED);
//        assertTrue(finishedMessage.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE);
//        System.out.println(finishedMessage.toString());
//        assertArrayEquals(finishedMessage.getVerifyData().getOriginalValue(),
//                ArrayConverter.hexStringToByteArray("C50EA95C9DFEBEBACF12C353"));
//        System.out.println(ArrayConverter.bytesToHexString(finishedMessage.getCompleteResultingMessage()
//                .getOriginalValue()));
//
//    }
//
//    @Test(expected = InvalidMessageTypeException.class)
//    public void testParseInvalidType() {
//        finishedHandler.setProtocolMessage(finishedMessage);
//        finishedHandler.parseMessageAction(ArrayConverter.hexStringToByteArray("1300000CC50EA95C9DFEBEBACF12C353"), 0);
//
//    }
//
//    @Test
//    public void testPrepareFuzzingMode() {
//        context.getConfig().setFuzzingMode(true);
//        finishedHandler.setProtocolMessage(finishedMessage);
//        finishedHandler.prepareMessageAction();
//        // We cannot assert anything since the algorithms are selected randomly
//    }
//
//    @Test
//    public void testPrepareMessageActionServer() {
//        context.getConfig().setMyConnectionEnd(ConnectionEnd.SERVER);
//        finishedHandler.setProtocolMessage(finishedMessage);
//        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CCM);
//        finishedHandler.prepareMessageAction();
//        assertTrue(finishedMessage.getHandshakeMessageType() == HandshakeMessageType.FINISHED);
//        assertTrue(finishedMessage.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE);
//        assertArrayEquals(finishedMessage.getVerifyData().getOriginalValue(),
//                ArrayConverter.hexStringToByteArray("A33B9CC92745BCF6C796AF7F"));
//        assertArrayEquals(finishedMessage.getCompleteResultingMessage().getOriginalValue(),
//                ArrayConverter.hexStringToByteArray("1400000CA33B9CC92745BCF6C796AF7F"));
//    }
//
//    // TODO throw better exception
//    @Test(expected = Exception.class)
//    public void testPrepareMessageActionWithoutMessage() {
//        finishedHandler.prepareMessageAction();
//    }
//
//    // TODO throw better exception
//    @Test(expected = Exception.class)
//    public void testParseMessageActionWithoutMessage() {
//        finishedHandler.parseMessage(ArrayConverter.hexStringToByteArray("1400000CA33B9CC92745BCF6C796AF7F"), 0);
//    }
//
//    @Test(expected = NoCiphersuiteSelectedException.class)
//    public void testPrepareMessageActionWithoutCiphersuiteSelected() {
//        finishedHandler.setProtocolMessage(finishedMessage);
//        finishedHandler.prepareMessageAction();
//    }
//
//    /**
//     * Test of parseMessageAction method, of class FinishedHandler.
//     */
//    @Test
//    public void testParseMessageActionFromServer() {
//        finishedHandler.setProtocolMessage(finishedMessage);
//        finishedHandler.parseMessageAction(ArrayConverter.hexStringToByteArray("1400000CA33B9CC92745BCF6C796AF7F"), 0);
//        assertArrayEquals(finishedMessage.getVerifyData().getOriginalValue(),
//                ArrayConverter.hexStringToByteArray("A33B9CC92745BCF6C796AF7F"));
//        assertArrayEquals(finishedMessage.getCompleteResultingMessage().getOriginalValue(),
//                ArrayConverter.hexStringToByteArray("1400000CA33B9CC92745BCF6C796AF7F"));
//
//    }
//
//    @Test
//    public void testParseMessageActionFromClient() {
//        finishedHandler.setProtocolMessage(finishedMessage);
//        finishedHandler.parseMessageAction(ArrayConverter.hexStringToByteArray("1400000CC50EA95C9DFEBEBACF12C353"), 0);
//        assertArrayEquals(finishedMessage.getVerifyData().getOriginalValue(),
//                ArrayConverter.hexStringToByteArray("C50EA95C9DFEBEBACF12C353"));
//        assertArrayEquals(finishedMessage.getCompleteResultingMessage().getOriginalValue(),
//                ArrayConverter.hexStringToByteArray("1400000CC50EA95C9DFEBEBACF12C353"));
//    }
//
//    @Test
//    public void testParseActionNotFromStart() {
//        finishedHandler.setProtocolMessage(finishedMessage);
//        finishedHandler.parseMessageAction(
//                ArrayConverter.hexStringToByteArray("00000000000000001400000CC50EA95C9DFEBEBACF12C353"), 8);
//        assertArrayEquals(finishedMessage.getVerifyData().getOriginalValue(),
//                ArrayConverter.hexStringToByteArray("C50EA95C9DFEBEBACF12C353"));
//        assertArrayEquals(finishedMessage.getCompleteResultingMessage().getOriginalValue(),
//                ArrayConverter.hexStringToByteArray("1400000CC50EA95C9DFEBEBACF12C353"));
//    }

}
