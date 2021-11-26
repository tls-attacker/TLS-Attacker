/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.SrtpProtectionProfiles;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SrtpExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.Arrays;
import java.util.List;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThat;
import org.junit.Before;
import org.junit.Test;

public class SrtpExtensionHandlerTest {

    private TlsContext context;
    private SrtpExtensionHandler handler;
    private final List<SrtpProtectionProfiles> profiles = Arrays.asList(
        SrtpProtectionProfiles.SRTP_AES128_CM_HMAC_SHA1_80, SrtpProtectionProfiles.SRTP_AES128_CM_HMAC_SHA1_32,
        SrtpProtectionProfiles.SRTP_NULL_HMAC_SHA1_80, SrtpProtectionProfiles.SRTP_NULL_HMAC_SHA1_32);
    private final byte[] profilesAsBytes = new byte[] { 0x00, 0x01, 0x00, 0x02, 0x00, 0x05, 0x00, 0x06 };
    private final byte[] mki = new byte[] {};

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new SrtpExtensionHandler(context);
    }

    @Test
    public void testadjustContext() {
        SrtpExtensionMessage msg = new SrtpExtensionMessage();
        msg.setSrtpProtectionProfiles(profilesAsBytes);
        msg.setSrtpMki(mki);

        handler.adjustContext(msg);

        assertThat(profiles, is(context.getSecureRealTimeTransportProtocolProtectionProfiles()));

        assertArrayEquals(mki, context.getSecureRealTimeProtocolMasterKeyIdentifier());
    }
}
