/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ice.serializer;

import de.rub.nds.tlsattacker.core.ice.model.SoftwareAttribute;

public class SoftwareAttributeSerializer extends StunAttributeSerializer<SoftwareAttribute> {

    public SoftwareAttributeSerializer(SoftwareAttribute attribute) {
        super(attribute);
    }

    @Override
    public byte[] serializeAttributeContent() {
        appendBytes(attribute.getSoftwareString().getValue().getBytes());
        return getAlreadySerialized();
    }
}
