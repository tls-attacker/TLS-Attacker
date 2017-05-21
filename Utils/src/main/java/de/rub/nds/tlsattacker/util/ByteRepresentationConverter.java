/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.util;

/**
 *
 * @author Janis Fliegenschmidt - janis.fliegenschmidt@rub.de
 */
public class ByteRepresentationConverter {

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();

        if (len % 2 != 0) {
            throw new IllegalArgumentException("Two hex symbols form a byte."
                    + " You might need padding on your input.");
        }

        byte[] data = new byte[len / 2];

        for (int i = 0; i < len; i += 2) {
            int a = Character.digit(s.charAt(i), 16);
            int b = Character.digit(s.charAt(i + 1), 16);

            if (a < 0 || b < 0) {
                throw new IllegalArgumentException("Argument contained" + " an illegal character");
            }

            data[i / 2] = (byte) ((a << 4) + b);
        }

        return data;
    }
}
