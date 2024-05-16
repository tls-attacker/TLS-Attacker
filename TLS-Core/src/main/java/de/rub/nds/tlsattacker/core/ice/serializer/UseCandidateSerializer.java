/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ice.serializer;

import de.rub.nds.tlsattacker.core.ice.model.UseCandidateAttribute;

public class UseCandidateSerializer extends StunAttributeSerializer<UseCandidateAttribute> {

    public UseCandidateSerializer(UseCandidateAttribute message) {
        super(message);
    }

    @Override
    public byte[] serializeAttributeContent() {
        // Nothing to do here
        return new byte[0];
    }
}
