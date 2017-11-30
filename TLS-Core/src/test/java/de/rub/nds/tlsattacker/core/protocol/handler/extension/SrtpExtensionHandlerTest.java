/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.SrtpProtectionProfiles;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SrtpExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SrtpExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.SrtpExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SrtpExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.Arrays;
import java.util.List;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
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
    public void testAdjustTLSContext() {
        SrtpExtensionMessage msg = new SrtpExtensionMessage();
        msg.setSrtpProtectionProfiles(profilesAsBytes);
        msg.setSrtpMki(mki);

        handler.adjustTLSContext(msg);

        assertThat(profiles, is(context.getSecureRealTimeTransportProtocolProtectionProfiles()));

        assertArrayEquals(mki, context.getSecureRealTimeProtocolMasterKeyIdentifier());
    }

    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[0], 0) instanceof SrtpExtensionParser);
    }

    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new SrtpExtensionMessage()) instanceof SrtpExtensionPreparator);
    }

    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new SrtpExtensionMessage()) instanceof SrtpExtensionSerializer);
    }
}
