/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer;

import de.rub.nds.tlsattacker.core.layer.constant.LayerType;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import java.util.List;

/**
 * Abstracts different ReceiveConfigurations. A ReceiveLayerConfiguration always specifies a list of
 * containers the layer should receive.
 *
 * @param <Container>
 */
public abstract class ReceiveLayerConfiguration<Container extends DataContainer>
        extends LayerConfiguration<Container> {

    public ReceiveLayerConfiguration(LayerType layerType, List<Container> containerList) {
        super(layerType, containerList);
    }

    public ReceiveLayerConfiguration(LayerType layerType, Container... containers) {
        super(layerType, containers);
    }

    public abstract boolean isProcessTrailingContainers();
}
