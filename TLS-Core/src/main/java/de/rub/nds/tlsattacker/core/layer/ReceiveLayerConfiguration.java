/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.layer;

import java.util.List;

import de.rub.nds.tlsattacker.core.layer.data.DataContainer;

/**
 * Abstracts different ReceiveConfigurations. A ReceiveLayerConfiguration always specifies a list of containers the
 * layer should receive.
 *
 * @param <Container>
 */
public abstract class ReceiveLayerConfiguration<Container extends DataContainer> extends LayerConfiguration<Container> {

    public ReceiveLayerConfiguration(List<Container> containerList) {
        super(containerList);
    }

    public ReceiveLayerConfiguration(Container... containers) {
        super(containers);
    }

    public abstract boolean isProcessTrailingContainers();
}
