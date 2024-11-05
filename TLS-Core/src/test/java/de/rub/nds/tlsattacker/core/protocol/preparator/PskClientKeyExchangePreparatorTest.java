/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.PskClientKeyExchangeMessage;
import org.junit.jupiter.api.Test;

public class PskClientKeyExchangePreparatorTest
        extends AbstractProtocolMessagePreparatorTest<
                PskClientKeyExchangeMessage, PskClientKeyExchangePreparator> {

    private static final String RANDOM = "CAFEBABECAFE";

    public PskClientKeyExchangePreparatorTest() {
        super(PskClientKeyExchangeMessage::new, PskClientKeyExchangePreparator::new);
    }

    /** Test of prepareHandshakeMessageContents method, of class PskClientKeyExchangePreparator. */
    @Test
    @Override
    public void testPrepare() {
        // prepare context
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA);
        tlsContext.setClientRandom(ArrayConverter.hexStringToByteArray(RANDOM));
        tlsContext.setServerRandom(ArrayConverter.hexStringToByteArray(RANDOM));
        preparator.prepareHandshakeMessageContents();

        // Tests
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("00040000000000041a2b3c4d"),
                message.getComputations().getPremasterSecret().getValue());
        assertNotNull(message.getComputations().getClientServerRandom());
        assertArrayEquals(
                ArrayConverter.concatenate(
                        ArrayConverter.hexStringToByteArray(RANDOM),
                        ArrayConverter.hexStringToByteArray(RANDOM)),
                message.getComputations().getClientServerRandom().getValue());
    }

    /** Test of prepareHandshakeMessageContents method, of class PskClientKeyExchangePreparator. */
    @Test
    public void testPrepareZeroLengthIdentifierAndPsk() {
        // prepare config
        tlsContext.getConfig().setDefaultPSKIdentity(new byte[0]);
        tlsContext.getConfig().setDefaultPSKKey(new byte[0]);
        // prepare context
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA);
        tlsContext.setClientRandom(ArrayConverter.hexStringToByteArray(RANDOM));
        tlsContext.setServerRandom(ArrayConverter.hexStringToByteArray(RANDOM));
        preparator.prepareHandshakeMessageContents();

        // Tests
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("00000000"),
                message.getComputations().getPremasterSecret().getValue());
        assertNotNull(message.getComputations().getClientServerRandom());
        assertArrayEquals(
                ArrayConverter.concatenate(
                        ArrayConverter.hexStringToByteArray(RANDOM),
                        ArrayConverter.hexStringToByteArray(RANDOM)),
                message.getComputations().getClientServerRandom().getValue());
    }
}
