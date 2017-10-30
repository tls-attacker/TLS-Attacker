/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 */
public class FinishedMessagePreparatorTest {

    private static final Logger LOGGER = LogManager.getLogger(FinishedMessagePreparatorTest.class);

    private FinishedMessage message;
    private TlsContext context;
    private FinishedMessagePreparator preparator;

    @Before
    public void setUp() {
        message = new FinishedMessage();
        context = new TlsContext();
        preparator = new FinishedMessagePreparator(context.getChooser(), message);
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
        context.setPrfAlgorithm(PRFAlgorithm.TLS_PRF_SHA256);
        preparator.prepare();
        LOGGER.info(ArrayConverter.bytesToHexString(message.getVerifyData().getValue(), false));
        assertArrayEquals(ArrayConverter.hexStringToByteArray("232A2CCB976E313AAA8E0F7A"), message.getVerifyData()
                .getValue());// TODO Did not check if this is calculated
        // correctly, just made sure it is set

    }

    /**
     * Test of prepareHandshakeMessageContents method for TLS 1.3, of class
     * FinishedMessagePreparator.
     */
    @Test
    public void testPrepareTLS13() {
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        context.setConnection(new OutboundConnection());
        context.setClientHandshakeTrafficSecret(ArrayConverter
                .hexStringToByteArray("2E9C9DD264A15D3C1EEC604A7C862934486764F94E35C0BA7E0B9494EAC06E82"));
        context.getDigest().setRawBytes(ArrayConverter.hexStringToByteArray("01010101010101010101010101010101"));
        preparator.prepare();
        assertArrayEquals(message.getVerifyData().getValue(),
                ArrayConverter.hexStringToByteArray("B4AB5C21316FD38E3605D62C9022062DA84D83214EBC7BCD4BE6B3DB1971AFCA"));
    }

    @Test
    public void testNoContextPrepare() {
        preparator.prepare();
    }

}
