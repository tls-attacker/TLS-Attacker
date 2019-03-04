/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.general;

import de.rub.nds.tlsattacker.core.protocol.parser.Parser;

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
