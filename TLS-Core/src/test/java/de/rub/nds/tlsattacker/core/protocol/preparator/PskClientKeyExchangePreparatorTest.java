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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.PskClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import org.junit.Before;
import org.junit.Test;

public class PskClientKeyExchangePreparatorTest {

    private final static String RANDOM = "CAFEBABECAFE";
    private final static byte[] PREMASTERSECRET = ArrayConverter.hexStringToByteArray("00040000000000041a2b3c4d");
    private TlsContext context;
    private PskClientKeyExchangeMessage message;
    private PskClientKeyExchangePreparator preparator;

    @Before
    public void setUp() {
        context = new TlsContext();
        message = new PskClientKeyExchangeMessage();
        preparator = new PskClientKeyExchangePreparator(context.getChooser(), message);
    }

    /**
     * Test of prepareHandshakeMessageContents method, of class
     * PskClientKeyExchangePreparator.
     */
    @Test
    public void testPrepare() {
        // prepare context
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedCipherSuite(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA);
        context.setClientRandom(ArrayConverter.hexStringToByteArray(RANDOM));
        context.setServerRandom(ArrayConverter.hexStringToByteArray(RANDOM));
        preparator.prepareHandshakeMessageContents();

        // Tests
        assertArrayEquals(PREMASTERSECRET, message.getComputations().getPremasterSecret().getValue());
        assertNotNull(message.getComputations().getClientServerRandom());
        assertArrayEquals(
                ArrayConverter.concatenate(ArrayConverter.hexStringToByteArray(RANDOM),
                        ArrayConverter.hexStringToByteArray(RANDOM)), message.getComputations().getClientServerRandom()
                        .getValue());

    }
}
