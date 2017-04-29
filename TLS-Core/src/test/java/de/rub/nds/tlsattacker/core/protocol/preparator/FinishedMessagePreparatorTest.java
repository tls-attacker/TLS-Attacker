/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.preparator.FinishedMessagePreparator;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class FinishedMessagePreparatorTest {

    private FinishedMessage message;
    private TlsContext context;
    private FinishedMessagePreparator preparator;

    public FinishedMessagePreparatorTest() {
    }

    @Before
    public void setUp() {
        message = new FinishedMessage();
        context = new TlsContext();
        preparator = new FinishedMessagePreparator(context, message);
    }

    /**
     * Test of prepareHandshakeMessageContents method, of class
     * FinishedMessagePreparator.
     */
    @Test
    public void testPrepare() {
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setMasterSecret(ArrayConverter.hexStringToByteArray("AABBCCDDEEFF"));
        preparator.prepare();
        LOGGER.info(ArrayConverter.bytesToHexString(message.getVerifyData().getValue(), false));
        assertArrayEquals(ArrayConverter.hexStringToByteArray("232A2CCB976E313AAA8E0F7A"), message.getVerifyData()
                .getValue());// TODO Did not check if this is calculated
                             // correctly, just made sure it is set

    }

    private static final Logger LOGGER = LogManager.getLogger(FinishedMessagePreparatorTest.class);
}
