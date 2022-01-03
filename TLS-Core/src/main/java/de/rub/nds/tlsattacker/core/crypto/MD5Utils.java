/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.crypto;

import org.bouncycastle.crypto.digests.MD5Digest;

public class MD5Utils {

    public static void md5Update(MD5Digest md5, byte[] bytes) {
        md5.update(bytes, 0, bytes.length);
    }

    public static byte[] md5(byte[]... byteArrays) {
        MD5Digest md5 = new MD5Digest();
        for (byte[] bytes : byteArrays) {
            md5Update(md5, bytes);
        }
        byte[] md5Output = new byte[md5.getDigestSize()];
        md5.doFinal(md5Output, 0);
        return md5Output;
    }

    private MD5Utils() {
    }

}
