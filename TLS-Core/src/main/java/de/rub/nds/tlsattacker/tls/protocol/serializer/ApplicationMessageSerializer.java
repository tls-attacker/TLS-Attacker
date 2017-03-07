/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer;

import de.rub.nds.tlsattacker.tls.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ApplicationMessageSerializer extends ProtocolMessageSerializer<ApplicationMessage> {

    private final ApplicationMessage message;

    public ApplicationMessageSerializer(ApplicationMessage message) {
        super(message);
        this.message = message;
    }

    @Override
    public byte[] serializeProtocolMessageContent() {
        appendBytes(message.getData().getValue());
        return getAlreadySerialized();
    }

}
