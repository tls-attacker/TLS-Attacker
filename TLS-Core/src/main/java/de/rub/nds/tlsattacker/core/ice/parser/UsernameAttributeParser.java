/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ice.parser;

import de.rub.nds.tlsattacker.core.ice.model.UsernameAttribute;
import de.rub.nds.tlsattacker.core.layer.context.IceContext;

import java.io.InputStream;

public class UsernameAttributeParser extends StunAttributeParser<UsernameAttribute> {

    public UsernameAttributeParser(IceContext context, InputStream stream) {
        super(context, stream);
    }

    @Override
    public void parse(UsernameAttribute attribute) {
        attribute.setUsername(new String(parseTillEnd()));
    }
}
