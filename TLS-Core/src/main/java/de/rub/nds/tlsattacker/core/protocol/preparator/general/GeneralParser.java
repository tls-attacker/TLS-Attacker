/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator.general;

import de.rub.nds.tlsattacker.core.protocol.Parser;

/**
 *
 *
 */
public class GeneralParser extends Parser {

    public GeneralParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    public int parseInteger(int length) {
        return parseIntField(length);
    }

    public byte[] parseTilEnd() {
        return parseArrayOrTillEnd(getBytesLeft());
    }

    @Override
    public Object parse() {
        throw new UnsupportedOperationException("Not supported yet."); // To
        // change
        // body
        // of
        // generated
        // methods,
        // choose
        // Tools
        // |
        // Templates.
    }

}
