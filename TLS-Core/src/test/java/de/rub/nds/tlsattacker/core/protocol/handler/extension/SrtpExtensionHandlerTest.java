/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.constants.SrtpProtectionProfiles;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SrtpExtensionMessage;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

public class SrtpExtensionHandlerTest
        extends AbstractExtensionMessageHandlerTest<SrtpExtensionMessage, SrtpExtensionHandler> {

    private final List<SrtpProtectionProfiles> profiles =
            Arrays.asList(
                    SrtpProtectionProfiles.SRTP_AES128_CM_HMAC_SHA1_80,
                            SrtpProtectionProfiles.SRTP_AES128_CM_HMAC_SHA1_32,
                    SrtpProtectionProfiles.SRTP_NULL_HMAC_SHA1_80,
                            SrtpProtectionProfiles.SRTP_NULL_HMAC_SHA1_32);
    private final byte[] profilesAsBytes =
            new byte[] {0x00, 0x01, 0x00, 0x02, 0x00, 0x05, 0x00, 0x06};
    private final byte[] mki = new byte[] {};

    public SrtpExtensionHandlerTest() {
        super(SrtpExtensionMessage::new, SrtpExtensionHandler::new);
    }

    @Test
    @Override
    public void testadjustTLSExtensionContext() {
        SrtpExtensionMessage msg = new SrtpExtensionMessage();
        msg.setSrtpProtectionProfiles(profilesAsBytes);
        msg.setSrtpMki(mki);
        handler.adjustTLSExtensionContext(msg);
        assertEquals(context.getSecureRealTimeTransportProtocolProtectionProfiles(), profiles);
        assertArrayEquals(mki, context.getSecureRealTimeProtocolMasterKeyIdentifier());
    }
}
