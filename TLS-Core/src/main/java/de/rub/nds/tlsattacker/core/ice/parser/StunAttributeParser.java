/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ice.parser;

import de.rub.nds.tlsattacker.core.ice.model.StunAttribute;
import de.rub.nds.tlsattacker.core.layer.context.IceContext;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.state.Context;
import java.io.InputStream;

/** A Parser class for the contents of the body of the respective attribute */
public abstract class StunAttributeParser<AttributeT extends StunAttribute>
        extends Parser<AttributeT> {

    protected IceContext iceContext;

    /**
     * An Input stream that contains the body (without padding) of the StunAttribute
     *
     * @param iceContext
     * @param stream
     */
    public StunAttributeParser(Context context, InputStream stream) {
        super(stream);
        this.iceContext = context.getIceContext();
    }
}
