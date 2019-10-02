/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.dtls;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import org.bouncycastle.util.Arrays;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class FragmentUtils {
    public static final int DEFAULT_MESSAGE_LENGTH = 10;

    public static DtlsHandshakeMessageFragment fragment(int messageSeq, int fragmentOffset, int fragmentLength,
            byte content[]) {
        DtlsHandshakeMessageFragment fragment = new DtlsHandshakeMessageFragment();
        fragment.setFragmentOffset(fragmentOffset);
        fragment.setFragmentLength(fragmentLength);
        fragment.setMessageSeq(messageSeq);
        fragment.setContent(content);
        fragment.setLength(DEFAULT_MESSAGE_LENGTH);
        fragment.setType(HandshakeMessageType.UNKNOWN.getValue());
        return fragment;
    }

    public static DtlsHandshakeMessageFragment fragment(int messageSeq, int fragmentOffset, int fragmentLength) {
        return fragment(messageSeq, fragmentOffset, fragmentLength, new byte[fragmentLength]);
    }

    public static DtlsHandshakeMessageFragment fragmentOfMsg(int messageSeq, int fragmentOffset, int fragmentLength,
            byte msgContent[]) {
        byte content[] = Arrays.copyOfRange(msgContent, fragmentOffset, fragmentOffset + fragmentLength);
        return fragment(messageSeq, fragmentOffset, fragmentLength, content);
    }

    public static void checkFragment(DtlsHandshakeMessageFragment fragment, int expectedOffset, int expectedLength,
            byte[] expectedContent) {
        assertNotNull(fragment);
        assertEquals(expectedOffset, fragment.getFragmentOffset().getValue().intValue());
        assertEquals(expectedLength, fragment.getFragmentLength().getValue().intValue());
        assertArrayEquals(expectedContent, fragment.getContent().getValue());
    }
}
