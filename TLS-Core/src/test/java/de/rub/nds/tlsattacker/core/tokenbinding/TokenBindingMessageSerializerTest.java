/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.tokenbinding;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class TokenBindingMessageSerializerTest {

    private TokenBindingMessageSerializer serializer;

    @BeforeEach
    public void setUp() {
        TokenBindingMessage message = new TokenBindingMessage();
        message.setExtensionBytes(new byte[0]);
        message.setExtensionLength(0);
        message.setKeyLength(0);
        message.setKeyParameter((byte) 0);
        message.setKeyParameter((byte) 0);
        message.setModulus(new byte[0]);
        message.setModulusLength(0);
        message.setPoint(new byte[0]);
        message.setPublicExponent(new byte[0]);
        message.setPublicExponentLength(0);
        message.setTokenbindingsLength(0);
        message.setTokenbindingType((byte) 0);
        message.setSignature(new byte[0]);
        message.setSignatureLength(0);
        message.setPointLength(0);
        ProtocolVersion version = ProtocolVersion.TLS12;

        serializer = new TokenBindingMessageSerializer(message);
    }

    /** Test of serializeBytes method, of class TokenBindingMessageSerializer. */
    @Test
    public void testSerializeBytes() {
        serializer.serialize();
    }
}
