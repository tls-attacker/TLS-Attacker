/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParametersExtensionMessage.PreferredAddress;
import java.io.IOException;
import org.junit.jupiter.api.Test;

class PreferredAddressConfigCopyTest {
    @Test
    void configCopyHandlesQuicPreferredAddress() throws IOException {
        Config config = new Config();
        byte[] encodedAddress = new byte[42];
        encodedAddress[0] = 127;
        encodedAddress[3] = 1;
        encodedAddress[6] = 0x20;
        encodedAddress[7] = 0x01;
        encodedAddress[8] = 0x0d;
        encodedAddress[9] = (byte) 0xb8;
        encodedAddress[24] = 1;
        encodedAddress[25] = 1;
        PreferredAddress preferredAddress = new PreferredAddress(encodedAddress);
        preferredAddress.setIpv4Port(443);
        preferredAddress.setIpv6Port(8443);
        byte[] serializedAddress = preferredAddress.serialize();
        config.getDefaultQuicTransportParameters().setPreferredAddress(preferredAddress);

        Config copiedConfig = config.createCopy();

        PreferredAddress copiedAddress =
                copiedConfig.getDefaultQuicTransportParameters().getPreferredAddress();
        assertNotNull(copiedAddress);
        assertEquals(preferredAddress.getIpv4Address(), copiedAddress.getIpv4Address());
        assertEquals(preferredAddress.getIpv4Port(), copiedAddress.getIpv4Port());
        assertEquals(preferredAddress.getIpv6Address(), copiedAddress.getIpv6Address());
        assertEquals(preferredAddress.getIpv6Port(), copiedAddress.getIpv6Port());
        assertArrayEquals(preferredAddress.getConnectionId(), copiedAddress.getConnectionId());
        assertArrayEquals(
                preferredAddress.getStatelessResetToken(), copiedAddress.getStatelessResetToken());
        assertArrayEquals(serializedAddress, copiedAddress.serialize());
    }
}
