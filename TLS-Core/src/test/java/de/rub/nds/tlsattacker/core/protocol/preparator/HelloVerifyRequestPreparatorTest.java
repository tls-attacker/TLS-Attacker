/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.preparator.HelloVerifyRequestPreparator;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class HelloVerifyRequestPreparatorTest {

    private TlsContext context;
    private HelloVerifyRequestPreparator preparator;
    private HelloVerifyRequestMessage message;

    public HelloVerifyRequestPreparatorTest() {
    }

    @Before
    public void setUp() {
        this.context = new TlsContext();
        this.message = new HelloVerifyRequestMessage();
        this.preparator = new HelloVerifyRequestPreparator(context, message);
    }

    /**
     * Test of prepareHandshakeMessageContents method, of class
     * HelloVerifyRequestPreparator.
     */
    @Test
    public void testPrepare() {
        RandomHelper.getRandom().setSeed(0);
        context.getConfig().setDefaultDTLSCookieLength(10);
        context.getConfig().setHighestProtocolVersion(ProtocolVersion.DTLS12);
        preparator.prepare();
        LOGGER.info(ArrayConverter.bytesToHexString(message.getCookie().getValue(), false));
        assertArrayEquals(ArrayConverter.hexStringToByteArray("60B420BB3851D9D47ACB"), message.getCookie().getValue());
        assertTrue(10 == message.getCookieLength().getValue());
        assertArrayEquals(ProtocolVersion.DTLS12.getValue(), message.getProtocolVersion().getValue());
    }

    private static final Logger LOGGER = LogManager.getLogger(HelloVerifyRequestPreparatorTest.class);

}
