/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.util;

import de.rub.nds.modifiablevariable.util.ArrayConverter;

/**
 *
 * @author Janis Fliegenschmidt - janis.fliegenschmidt@rub.de
 */
public class ByteRepresentationConverter {

    public static byte[] hexStringToByteArray(String s) {
        return ArrayConverter.hexStringToByteArray(s);
    }
}
