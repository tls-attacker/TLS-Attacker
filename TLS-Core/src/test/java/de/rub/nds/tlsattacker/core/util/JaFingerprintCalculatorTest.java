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
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
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
        renegotiationInfoExtensionMessage = new RenegotiationInfoExtensionMessage();
        renegotiationInfoExtensionMessage.setExtensionType(
                ExtensionType.RENEGOTIATION_INFO.getValue());
        EllipticCurvesExtensionMessage ellipticCurvesExtensionMessage =
                new EllipticCurvesExtensionMessage();
        ellipticCurvesExtensionMessage.setExtensionType(ExtensionType.ELLIPTIC_CURVES.getValue());

        SignatureAndHashAlgorithmsExtensionMessage signatureAndHashAlgorithmsExtensionMessage =
                new SignatureAndHashAlgorithmsExtensionMessage();
        signatureAndHashAlgorithmsExtensionMessage.setExtensionType(
                ExtensionType.SIGNATURE_AND_HASH_ALGORITHMS.getValue());
        ecPointFormatExtensionMessage.setPointFormats(new byte[] {0x00});
        extensions.add(ecPointFormatExtensionMessage);
        extensions.add(ellipticCurvesExtensionMessage);
        ellipticCurvesExtensionMessage.setSupportedGroups(
                ArrayConverter.hexStringToByteArray(
                        "000f0010001100120013001400150016001700180019000100020003000400050006000700080009000a000b000c000d000e001d001e0029001a001b001c01000101010201030104"));
        extensions.add(signatureAndHashAlgorithmsExtensionMessage);
        extensions.add(renegotiationInfoExtensionMessage);

        clientHelloMessage = new ClientHelloMessage();
        clientHelloMessage.setProtocolVersion(new byte[] {0x03, 0x03});
        clientHelloMessage.setCipherSuites(new byte[] {(byte) 0xC0, 0x0A});
        clientHelloMessage.setExtensions(extensions);
    }

    @Test
    void testGetJa3FingerprintHash() {
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("8042c60060dd584f09b72dc10430bab0"),
                JaFingerprintCalculator.getJa3FingerprintHash(clientHelloMessage));
    }

    @Test
    void testGetJa3FingerprintString() {
        assertEquals(
                "771,49162,11-10-13-65281,15-16-17-18-19-20-21-22-23-24-25-1-2-3-4-5-6-7-8-9-10-11-12-13-14-29-30-41-26-27-28-256-257-258-259-260,0",
                JaFingerprintCalculator.getJa3FingerprintString(clientHelloMessage));
    }

    @Test
    void testGetJa3sFingerprintHash() {
        assertArrayEquals(
                JaFingerprintCalculator.getJa3sFingerprintHash(serverHelloMessage),
                ArrayConverter.hexStringToByteArray("9c926772457508cd61564bfd25323dae"));
    }

    @Test
    void testGetJa3sFingerprintString() {
        assertEquals(
                "771,49162,11-65281",
                JaFingerprintCalculator.getJa3sFingerprintString(serverHelloMessage));
    }
}
