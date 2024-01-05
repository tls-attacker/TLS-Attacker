/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;

public class ClientHelloSerializer extends CoreClientHelloSerializer<ClientHelloMessage> {
    /**
     * Constructor for the ClientHelloSerializer
     *
     * @param message Message that should be serialized
     * @param version
     */
    public ClientHelloSerializer(ClientHelloMessage message, ProtocolVersion version) {
        super(message, version);
    }
}
