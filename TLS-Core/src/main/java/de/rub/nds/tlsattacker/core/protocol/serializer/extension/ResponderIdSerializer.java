/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.ResponderId;
import de.rub.nds.tlsattacker.core.protocol.serializer.Serializer;

public class ResponderIdSerializer extends Serializer<ResponderId> {

    private final ResponderId id;

    public ResponderIdSerializer(ResponderId id) {
        this.id = id;
    }

    @Override
    protected byte[] serializeBytes() {
        appendInt(id.getIdLength().getValue(), ExtensionByteLength.CERTIFICATE_STATUS_REQUEST_V2_RESPONDER_ID);
        appendBytes(id.getId().getValue());

        return getAlreadySerialized();
    }

}
