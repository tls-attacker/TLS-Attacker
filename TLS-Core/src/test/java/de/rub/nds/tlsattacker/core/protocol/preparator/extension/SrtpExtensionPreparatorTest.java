/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.SrtpProtectionProfiles;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SrtpExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SrtpExtensionSerializer;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

public class SrtpExtensionPreparatorTest
        extends AbstractExtensionMessagePreparatorTest<
                SrtpExtensionMessage, SrtpExtensionSerializer, SrtpExtensionPreparator> {

    public SrtpExtensionPreparatorTest() {
        super(
                SrtpExtensionMessage::new,
                SrtpExtensionSerializer::new,
                SrtpExtensionPreparator::new);
    }

    @Test
    @Override
    public void testPrepare() {
        List<SrtpProtectionProfiles> profiles =
                Arrays.asList(
                        SrtpProtectionProfiles.SRTP_AES128_CM_HMAC_SHA1_80,
                        SrtpProtectionProfiles.SRTP_AES128_CM_HMAC_SHA1_32,
                        SrtpProtectionProfiles.SRTP_NULL_HMAC_SHA1_80,
                        SrtpProtectionProfiles.SRTP_NULL_HMAC_SHA1_32);
        byte[] mki = new byte[0];
        context.getConfig().setSecureRealTimeTransportProtocolProtectionProfiles(profiles);
        context.getConfig().setSecureRealTimeTransportProtocolMasterKeyIdentifier(mki);

        preparator.prepare();

        assertArrayEquals(ExtensionType.USE_SRTP.getValue(), message.getExtensionType().getValue());
        assertArrayEquals(
                new byte[] {0x00, 0x01, 0x00, 0x02, 0x00, 0x05, 0x00, 0x06},
                message.getSrtpProtectionProfiles().getValue());
        assertEquals(8, message.getSrtpProtectionProfilesLength().getValue());
        assertArrayEquals(mki, message.getSrtpMki().getValue());
        assertEquals(0, message.getSrtpMkiLength().getValue());
    }
}
