/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.context;

import de.rub.nds.tlsattacker.core.protocol.Parser;

public interface ParserContext {

    ParserContextResult beforeParse(Parser p, int length, ParserContext previous);

}