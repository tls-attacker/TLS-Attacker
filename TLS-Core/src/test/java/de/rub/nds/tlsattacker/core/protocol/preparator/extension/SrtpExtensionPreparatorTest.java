/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.SrtpProtectionProfiles;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SrtpExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SrtpExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.Arrays;
import java.util.List;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

public class SrtpExtensionPreparatorTest {

    private TlsContext context;
    private SrtpExtensionPreparator preparator;
    private SrtpExtensionMessage msg;
    private final List<SrtpProtectionProfiles> profiles = Arrays.asList(
            SrtpProtectionProfiles.SRTP_AES128_CM_HMAC_SHA1_80, SrtpProtectionProfiles.SRTP_AES128_CM_HMAC_SHA1_32,
            SrtpProtectionProfiles.SRTP_NULL_HMAC_SHA1_80, SrtpProtectionProfiles.SRTP_NULL_HMAC_SHA1_32);
    private final int profilesLength = 8;
    private final byte[] profilesAsBytes = new byte[] { 0x00, 0x01, 0x00, 0x02, 0x00, 0x05, 0x00, 0x06 };
    private final byte[] mki = new byte[] {};
    private final int mkiLength = 0;

    @Before
    public void setUp() {
        context = new TlsContext();
        msg = new SrtpExtensionMessage();
        preparator = new SrtpExtensionPreparator(context.getChooser(), msg, new SrtpExtensionSerializer(msg));
    }

    @Test
    public void testPreparator() {
        context.getConfig().setSecureRealTimeTransportProtocolProtectionProfiles(profiles);
        context.getConfig().setSecureRealTimeTransportProtocolMasterKeyIdentifier(mki);

        preparator.prepare();

        assertArrayEquals(ExtensionType.USE_SRTP.getValue(), msg.getExtensionType().getValue());
        assertArrayEquals(profilesAsBytes, msg.getSrtpProtectionProfiles().getValue());
        assertEquals(profilesLength, (long) msg.getSrtpProtectionProfilesLength().getValue());
        assertArrayEquals(mki, msg.getSrtpMki().getValue());
        assertEquals(mkiLength, (long) msg.getSrtpMkiLength().getValue());

    }

}
