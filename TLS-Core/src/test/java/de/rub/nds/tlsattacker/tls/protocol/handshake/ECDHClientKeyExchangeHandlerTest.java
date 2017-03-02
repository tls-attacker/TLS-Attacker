/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake;

import de.rub.nds.tlsattacker.tls.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.BigIntegerModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.handler.ECDHClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.ECDHEServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.math.BigInteger;
import org.junit.Assert;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ECDHClientKeyExchangeHandlerTest {

//    BigInteger testBaseX = new BigInteger(
//            "33c4c75900f942cd601a447b760b4bad525aaee2d085436be599d07b7a01875d1c160981fabd4ad387e5cb81927be6b0b9ef5f8e8"
//                    + "48c574abc273026b422de325eeb142b575f1fa", 16);
//
//    BigInteger testBaseY = new BigInteger(
//            "2685a47e3b85fef3928fd544e3ba990f05f6fc71a36c0ec4833b8cda466b63a959900ade937a8c832342407acce32a4e2d1c37f63"
//                    + "835a31dc29ff8cf4f5720bb5e33e3e8a22cba6", 16);
//
//    ECDHClientKeyExchangeHandler handler;
//
//    ECDHEServerKeyExchangeHandler skeHandler;
//
//    public ECDHClientKeyExchangeHandlerTest() {
//        TlsContext context = new TlsContext(new TlsConfig());
//        context.setSelectedCipherSuite(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA);
//        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
//        handler = new ECDHClientKeyExchangeHandler(context);
//
//        // initialize tls context with ec parameters
//        skeHandler = new ECDHEServerKeyExchangeHandler(context);
//        byte[] serverKeyExchangeBytes = testServerKeyExchangeECDSA;
//        skeHandler.initializeProtocolMessage();
//        skeHandler.parseMessageAction(serverKeyExchangeBytes, 0);
//    }
//
//    /**
//     * Test of prepareMessageAction method, of class
//     * ECDHClientKeyExchangeHandler.
//     */
//    @Test
//    public void testPrepareMessage() {
//        handler.initializeProtocolMessage();
//
//        ECDHClientKeyExchangeMessage message = handler.getProtocolMessage();
//        ModifiableBigInteger mvx = new ModifiableBigInteger();
//        mvx.setModification(BigIntegerModificationFactory.explicitValue(testBaseX));
//        message.setPublicKeyBaseX(mvx);
//        ModifiableBigInteger mvy = new ModifiableBigInteger();
//        mvy.setModification(BigIntegerModificationFactory.explicitValue(testBaseY));
//        message.setPublicKeyBaseY(mvy);
//
//        byte[] result = handler.prepareMessageAction();
//
//        assertEquals("Message type must be ClientKeyExchange", HandshakeMessageType.CLIENT_KEY_EXCHANGE,
//                message.getHandshakeMessageType());
//
//        byte[] points = ArrayConverter.concatenate(testBaseX.toByteArray(), testBaseY.toByteArray());
//
//        byte[] expected = ArrayConverter.concatenate(new byte[] { 0x10, 0x00, 0x00, (byte) 0x92,
//                (byte) (points.length + 1), 0x04 }, points);
//
//        Assert.assertArrayEquals(expected, result);
//
//    }

}
