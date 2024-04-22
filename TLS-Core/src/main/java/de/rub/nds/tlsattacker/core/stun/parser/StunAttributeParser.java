/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.stun.parser;

import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.stun.IceContext;
import de.rub.nds.tlsattacker.core.stun.model.StunAttribute;
import java.io.InputStream;

/** A Parser class for the contents of the body of the respective attribute */
public abstract class StunAttributeParser<AttributeT extends StunAttribute>
        extends Parser<AttributeT> {

    protected IceContext context;

    /**
     * An Input stream that contains the body (without padding) of the StunAttribute
     *
     * @param context
     * @param stream
     */
    public StunAttributeParser(IceContext context, InputStream stream) {
        super(stream);
        this.context = context;
    }
}
