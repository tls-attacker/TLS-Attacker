/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tcp;

import de.rub.nds.tlsattacker.core.layer.data.Handler;

public class TcpStreamContainerHandler extends Handler<TcpStreamContainer> {

    @Override
    public void adjustContext(TcpStreamContainer container) {}
}
