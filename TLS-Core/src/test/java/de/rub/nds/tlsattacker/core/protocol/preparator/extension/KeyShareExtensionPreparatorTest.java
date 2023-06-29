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

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.KeyShareExtensionSerializer;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.Test;

public class KeyShareExtensionPreparatorTest
        extends AbstractExtensionMessagePreparatorTest<
                KeyShareExtensionMessage,
                KeyShareExtensionSerializer,
                KeyShareExtensionPreparator> {

    public KeyShareExtensionPreparatorTest() {
        super(
                KeyShareExtensionMessage::new,
                msg -> new KeyShareExtensionSerializer(msg, ConnectionEndType.CLIENT),
                KeyShareExtensionPreparator::new);
    }

    /** Test of prepare method, of class KeyShareExtensionPreparator. */
    @Test
    @Override
    public void testPrepare() {
        List<KeyShareEntry> keyShareList = new LinkedList<>();
        KeyShareEntry entry =
                new KeyShareEntry(
                        NamedGroup.ECDH_X25519,
                        new BigInteger(
                                "03BD8BCA70C19F657E897E366DBE21A466E4924AF6082DBDF573827BCDDE5DEF",
                                16));
        keyShareList.add(entry);
        message.setKeyShareList(keyShareList);
        preparator.prepare();
        assertArrayEquals(
                message.getKeyShareListBytes().getValue(),
                ArrayConverter.hexStringToByteArray(
                        "001D00202a981db6cdd02a06c1763102c9e741365ac4e6f72b3176a6bd6a3523d3ec0f4c"));
        assertEquals(36, (int) message.getKeyShareListLength().getValue());
    }

    /** Test of prepare method, of class KeyShareExtensionPreparator. */
    @Test
    public void testPreparePWD() {
        context.setSelectedCipherSuite(CipherSuite.TLS_ECCPWD_WITH_AES_128_GCM_SHA256);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        List<KeyShareEntry> keyShareList = new LinkedList<>();
        KeyShareEntry entry = new KeyShareEntry(NamedGroup.BRAINPOOLP256R1, BigInteger.ZERO);
        keyShareList.add(entry);
        message.setKeyShareList(keyShareList);
        preparator.prepare();
        assertEquals(101, (long) message.getKeyShareListLength().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        ("00 1A 00 61 9E E1 7F 2E  CF 74 02 8F 6C 1F D7 0D\n"
                                        + "A1 D0 5A 4A 85 97 5D 7D  27 0C AA 6B 86 05 F1 C6\n"
                                        + "EB B8 75 BA 87 57 91 67  40 8F 7C 9E 77 84 2C 2B\n"
                                        + "3F 33 68 A2 5F D1 65 63  7E 9B 5D 57 76 0B 0B 70\n"
                                        + "46 59 B8 74 20 66 92 44  AA 67 CB 00 EA 72 C0 9B\n"
                                        + "84 A9 DB 5B B8 24 FC 39  82 42 8F CD 40 69 63 AE\n"
                                        + "08 0E 67 7A 48")
                                .replaceAll("\\s+", "")),
                message.getKeyShareListBytes().getValue());
    }
}
