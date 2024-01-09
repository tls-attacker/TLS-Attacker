/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tcp;

import de.rub.nds.tlsattacker.core.layer.data.Serializer;

public class TcpStreamContainerSerializer extends Serializer<TcpStreamContainer> {

    private TcpStreamContainer streamContainer;

    public TcpStreamContainerSerializer(TcpStreamContainer streamContainer) {
        super();
        this.streamContainer = streamContainer;
    }

    @Override
    protected byte[] serializeBytes() {
        return streamContainer.getData().getValue();
    }
}
