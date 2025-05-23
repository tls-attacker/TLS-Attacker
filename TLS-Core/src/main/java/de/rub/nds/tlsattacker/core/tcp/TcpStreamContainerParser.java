/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.tcp;

import de.rub.nds.tlsattacker.core.layer.data.Parser;
import java.io.InputStream;

public class TcpStreamContainerParser extends Parser<TcpStreamContainer> {

    public TcpStreamContainerParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(TcpStreamContainer container) {
        container.setData(parseTillEnd());
    }
}
