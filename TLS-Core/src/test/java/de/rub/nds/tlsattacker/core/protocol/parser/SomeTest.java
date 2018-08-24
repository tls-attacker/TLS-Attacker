/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;

public class SomeTest {

    public void test() {
        ServerHelloParser parser = new ServerHelloParser(
                0,
                ArrayConverter
                        .hexStringToByteArray("020000560303efa16312095c8e65508f5d7ff45e917678ed2f1dd2a39c12d9ca55d785e12b9300130100002e002b00027f1600280024001d00206dacd29525eef4a3a3d1e3e20d9c567dbbab2bd9a01a526bb9d5afa335e94024"),
                ProtocolVersion.TLS13);
        ServerHelloMessage parse = parser.parse();
    }
}
