/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class JaFingerprintCalculatorTest {

    private ServerHelloMessage serverHelloMessage;

    private ClientHelloMessage clientHelloMessage;

    @BeforeEach
    void setUp() {
        serverHelloMessage = new ServerHelloMessage();
        serverHelloMessage.setProtocolVersion(new byte[] {0x03, 0x03});
        serverHelloMessage.setSelectedCipherSuite(new byte[] {(byte) 0xC0, 0x0A});
        List<ExtensionMessage> extensions = new LinkedList<>();
        ECPointFormatExtensionMessage ecPointFormatExtensionMessage =
                new ECPointFormatExtensionMessage();
        ecPointFormatExtensionMessage.setExtensionType(ExtensionType.EC_POINT_FORMATS.getValue());
        extensions.add(ecPointFormatExtensionMessage);
        RenegotiationInfoExtensionMessage renegotiationInfoExtensionMessage =
                new RenegotiationInfoExtensionMessage();
        renegotiationInfoExtensionMessage.setExtensionType(
                ExtensionType.RENEGOTIATION_INFO.getValue());
        extensions.add(renegotiationInfoExtensionMessage);

        serverHelloMessage.setExtensions(extensions);

        extensions = new LinkedList<>();
        ecPointFormatExtensionMessage = new ECPointFormatExtensionMessage();
        ecPointFormatExtensionMessage.setExtensionType(ExtensionType.EC_POINT_FORMATS.getValue());
        extensions.add(ecPointFormatExtensionMessage);
        renegotiationInfoExtensionMessage = new RenegotiationInfoExtensionMessage();
        renegotiationInfoExtensionMessage.setExtensionType(
                ExtensionType.RENEGOTIATION_INFO.getValue());
        extensions.add(renegotiationInfoExtensionMessage);
        EllipticCurvesExtensionMessage ellipticCurvesExtensionMessage =
                new EllipticCurvesExtensionMessage();
        ellipticCurvesExtensionMessage.setExtensionType(ExtensionType.ELLIPTIC_CURVES.getValue());
        extensions.add(ellipticCurvesExtensionMessage);

        extensions.add(ecPointFormatExtensionMessage);
        extensions.add(renegotiationInfoExtensionMessage);
        extensions.add(ellipticCurvesExtensionMessage);

        clientHelloMessage = new ClientHelloMessage();
        clientHelloMessage.setProtocolVersion(new byte[] {0x03, 0x03});
        clientHelloMessage.setCipherSuites(new byte[] {(byte) 0xC0, 0x0A});
        clientHelloMessage.setExtensions(extensions);
    }

    @Test
    void testGetJa3FingerprintHash() {}

    @Test
    void testGetJa3FingerprintString() {}

    @Test
    void testGetJa3sFingerprintHash() {
        assertArrayEquals(
                JaFingerprintCalculator.getJa3sFingerprintHash(serverHelloMessage),
                ArrayConverter.hexStringToByteArray("9c926772457508cd61564bfd25323dae"));
    }

    @Test
    void testGetJa3sFingerprintString() {}
}
