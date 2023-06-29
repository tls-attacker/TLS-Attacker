/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import java.util.function.BiConsumer;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class CertificateMessageTest extends AbstractMessageTest<CertificateMessage> {

    public CertificateMessageTest() {
        super(
                CertificateMessage::new,
                "CertificateMessage:\n"
                        + "  Certificates Length: %s\n"
                        + "  Certificate:\n"
                        + "%s");
    }

    public static Stream<Arguments> provideToStringTestVectors() {
        BiConsumer<CertificateMessage, Object[]> messagePreparator =
                (message, values) -> {
                    message.setCertificatesListLength((byte) values[0]);
                    message.setCertificatesListBytes((byte[]) values[1]);
                };
        return Stream.of(
                Arguments.of(new Object[] {null, null}, null),
                Arguments.of(new Object[] {(byte) 120, new byte[] {120}}, messagePreparator));
    }
}
