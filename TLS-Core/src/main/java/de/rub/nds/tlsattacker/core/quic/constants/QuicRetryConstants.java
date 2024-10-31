/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.constants;

import de.rub.nds.modifiablevariable.util.ArrayConverter;

public class QuicRetryConstants {

    public static final byte[] QUIC1_RETRY_INTEGRITY_TAG_KEY =
            ArrayConverter.hexStringToByteArray("be0c690b9f66575a1d766b54e368c84e");
    public static final byte[] QUIC2_RETRY_INTEGRITY_TAG_KEY =
            ArrayConverter.hexStringToByteArray("8fb4b01b56ac48e260fbcbcead7ccc92");
    public static final byte[] QUIC1_RETRY_INTEGRITY_TAG_IV =
            ArrayConverter.hexStringToByteArray("461599d35d632bf2239825bb");
    public static final byte[] QUIC2_RETRY_INTEGRITY_TAG_IV =
            ArrayConverter.hexStringToByteArray("d86969bc2d7c6d9990efb04a");

    private QuicRetryConstants() {}
}
