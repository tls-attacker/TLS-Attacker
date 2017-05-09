/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SNI.ServerNamePair;
import de.rub.nds.tlsattacker.core.protocol.parser.Parser;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ServerNamePairParser extends Parser<ServerNamePair> {

    public ServerNamePairParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public ServerNamePair parse() {
        ServerNamePair pair = new ServerNamePair();
        pair.setServerNameType(parseByteField(ExtensionByteLength.SERVER_NAME_TYPE));
        pair.setServerNameLength(parseIntField(ExtensionByteLength.SERVER_NAME_LENGTH));
        pair.setServerName(parseByteArrayField(pair.getServerNameLength().getValue()));
        return pair;
    }

}
