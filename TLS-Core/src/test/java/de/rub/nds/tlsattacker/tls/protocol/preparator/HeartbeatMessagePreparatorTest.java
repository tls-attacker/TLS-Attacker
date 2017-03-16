/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator;

import de.rub.nds.tlsattacker.tls.constants.HeartbeatMessageType;
import de.rub.nds.tlsattacker.tls.constants.HeartbeatMode;
import de.rub.nds.tlsattacker.tls.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import de.rub.nds.tlsattacker.util.RandomHelper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class HeartbeatMessagePreparatorTest {

    private TlsContext context;
    private HeartbeatMessage message;
    private HeartbeatMessagePreparator preparator;

    public HeartbeatMessagePreparatorTest() {
    }

    @Before
    public void setUp() {
        this.context = new TlsContext();
        this.message = new HeartbeatMessage();
        this.preparator = new HeartbeatMessagePreparator(context, message);
        RandomHelper.getRandom().setSeed(0);
    }

    /**
     * Test of prepareProtocolMessageContents method, of class
     * HeartbeatMessagePreparator.
     */
    @Test
    public void testPrepare() {
        context.getConfig().setHeartbeatPayloadLength(11);
        context.getConfig().setHeartbeatMaxPaddingLength(11);
        context.getConfig().setHeartbeatMinPaddingLength(5);
        preparator.prepare();
        assertTrue(HeartbeatMessageType.HEARTBEAT_REQUEST.getValue() == message.getHeartbeatMessageType().getValue());
        LOGGER.info("padding: " + ArrayConverter.bytesToHexString(message.getPadding().getValue()));
        LOGGER.info("payload: " + ArrayConverter.bytesToHexString(message.getPayload().getValue()));

        assertArrayEquals(ArrayConverter.hexStringToByteArray("F6C92DA33AF01D4FB770"), message.getPadding().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("60B420BB3851D9D47ACB93"), message.getPayload()
                .getValue());
        assertTrue(11 == message.getPayloadLength().getValue());
    }

    private static final Logger LOGGER = LogManager.getLogger(HeartbeatMessagePreparatorTest.class);

}
