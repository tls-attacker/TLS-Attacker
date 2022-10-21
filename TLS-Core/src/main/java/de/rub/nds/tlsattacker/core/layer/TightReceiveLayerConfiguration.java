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

import de.rub.nds.tlsattacker.core.layer.constant.LayerType;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;

/**
 * Very similar to {@link SpecificReceiveLayerConfiguration} but does not continue receiving containers when the
 * specified containers have been received.
 * 
 * @param <Container>
 */
public class TightReceiveLayerConfiguration<Container extends DataContainer>
    extends SpecificReceiveLayerConfiguration<Container> {

    public TightReceiveLayerConfiguration(LayerType layerType, List<Container> containerList) {
        super(layerType, containerList);
    }

    public TightReceiveLayerConfiguration(LayerType layerType, Container... containers) {
        super(layerType, containers);
    }

    @Override
    public boolean isProcessTrailingContainers() {
        return false;
    }
}
