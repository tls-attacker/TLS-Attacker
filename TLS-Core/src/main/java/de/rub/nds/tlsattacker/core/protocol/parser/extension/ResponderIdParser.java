/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.ResponderId;
import de.rub.nds.tlsattacker.core.protocol.Parser;

public class ResponderIdParser extends Parser<ResponderId> {

    public ResponderIdParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public ResponderId parse() {
        ResponderId id = new ResponderId();
        id.setIdLength(parseIntField(ExtensionByteLength.CERTIFICATE_STATUS_REQUEST_V2_RESPONDER_ID));
        id.setId(parseByteArrayField(id.getIdLength().getValue()));
        return id;
    }

}
