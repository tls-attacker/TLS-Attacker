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
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class ReceiveTillLayerConfiguration<Container extends DataContainer>
        extends ReceiveLayerConfiguration<Container> {

    public ReceiveTillLayerConfiguration(LayerType layerType, Container expectedContainer) {
        super(layerType, Arrays.asList(expectedContainer));
    }

    /**
     * Checks whether no other containers than the ones specified were received.
     *
     * @param list The list of DataContainers
     * @return
     */
    @Override
    public boolean executedAsPlanned(List<Container> list) {
        // holds containers we expect
        List<Class<? extends DataContainer>> missingExpectedContainers =
                getContainerList().stream()
                        .map(DataContainer::getClass)
                        .collect(Collectors.toList());
        // for each container we received remove it from the expected ones to be left with any
        // additional containers
        if (list != null) {
            list.forEach(
                    receivedContainer ->
                            missingExpectedContainers.remove(receivedContainer.getClass()));
        }
        return missingExpectedContainers.isEmpty();
    }

    @Override
    public boolean failedEarly(List<Container> list) {
        return false;
    }

    @Override
    public boolean isProcessTrailingContainers() {
        return true;
    }
}
