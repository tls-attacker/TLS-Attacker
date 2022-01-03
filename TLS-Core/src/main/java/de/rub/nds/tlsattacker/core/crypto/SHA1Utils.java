/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.crypto;

import org.bouncycastle.crypto.digests.SHA1Digest;

public class SHA1Utils {

    public static void sha1Update(SHA1Digest sha1, byte[] bytes) {
        sha1.update(bytes, 0, bytes.length);
    }

    public static byte[] sha1(byte[]... byteArrays) {
        SHA1Digest sha1 = new SHA1Digest();
        for (byte[] bytes : byteArrays) {
            sha1Update(sha1, bytes);
        }
        byte[] sha1Output = new byte[sha1.getDigestSize()];
        sha1.doFinal(sha1Output, 0);
        return sha1Output;
    }

    private SHA1Utils() {
    }

}
