/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants.stun;

import de.rub.nds.modifiablevariable.util.ArrayConverter;

public class StunVersionCookie {
    public static final byte[] RFC5389_VERSION = ArrayConverter.hexStringToByteArray("2112a442");
}
