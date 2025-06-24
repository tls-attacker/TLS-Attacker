/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.constants;

import de.rub.nds.modifiablevariable.util.DataConverter;
import java.util.Arrays;

public class QuicRetryConstants {

    private static final byte[] QUIC1_RETRY_INTEGRITY_TAG_KEY =
            DataConverter.hexStringToByteArray("be0c690b9f66575a1d766b54e368c84e");
    private static final byte[] QUIC2_RETRY_INTEGRITY_TAG_KEY =
            DataConverter.hexStringToByteArray("8fb4b01b56ac48e260fbcbcead7ccc92");
    private static final byte[] QUIC1_RETRY_INTEGRITY_TAG_IV =
            DataConverter.hexStringToByteArray("461599d35d632bf2239825bb");
    private static final byte[] QUIC2_RETRY_INTEGRITY_TAG_IV =
            DataConverter.hexStringToByteArray("d86969bc2d7c6d9990efb04a");

    public static byte[] getQuic1RetryIntegrityTagKey() {
        return Arrays.copyOf(QUIC1_RETRY_INTEGRITY_TAG_KEY, QUIC1_RETRY_INTEGRITY_TAG_KEY.length);
    }

    public static byte[] getQuic2RetryIntegrityTagKey() {
        return Arrays.copyOf(QUIC2_RETRY_INTEGRITY_TAG_KEY, QUIC2_RETRY_INTEGRITY_TAG_KEY.length);
    }

    public static byte[] getQuic1RetryIntegrityTagIv() {
        return Arrays.copyOf(QUIC1_RETRY_INTEGRITY_TAG_IV, QUIC1_RETRY_INTEGRITY_TAG_IV.length);
    }

    public static byte[] getQuic2RetryIntegrityTagIv() {
        return Arrays.copyOf(QUIC2_RETRY_INTEGRITY_TAG_IV, QUIC2_RETRY_INTEGRITY_TAG_IV.length);
    }

    private QuicRetryConstants() {}
}
