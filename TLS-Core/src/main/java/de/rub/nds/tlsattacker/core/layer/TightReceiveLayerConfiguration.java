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
import java.util.stream.Collectors;
import org.apache.logging.log4j.Level;

/**
 * Very similar to {@link SpecificReceiveLayerConfiguration} but does not continue receiving
 * containers when the specified containers have been received.
 *
 * @param <Container>
 */
public class TightReceiveLayerConfiguration<Container extends DataContainer>
        extends SpecificReceiveLayerConfiguration<Container> {

    public TightReceiveLayerConfiguration(LayerType layerType, List<Container> containerList) {
        super(layerType, containerList);
    }

    @SafeVarargs
    public TightReceiveLayerConfiguration(LayerType layerType, Container... containers) {
        super(layerType, containers);
    }

    @Override
    public boolean shouldContinueProcessing(
            List<Container> list, boolean receivedTimeout, boolean dataLeftToProcess) {
        if (receivedTimeout) {
            return false;
        }
        return !evaluateReceivedContainers(list, true);
    }

    @Override
    public String toCompactString() {
        return "("
                + getLayerType().getName()
                + ") TightReceive:"
                + getContainerList().stream()
                        .map(DataContainer::toCompactString)
                        .collect(Collectors.joining(","));
    }

    @Override
    public boolean shouldBeLogged(Level level) {
        return true;
    }
}
