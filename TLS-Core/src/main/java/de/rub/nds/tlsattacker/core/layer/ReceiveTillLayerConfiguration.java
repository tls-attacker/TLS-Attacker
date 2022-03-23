/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.layer;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class ReceiveTillLayerConfiguration<Container extends DataContainer>
    extends ReceiveLayerConfiguration<Container> {

    public ReceiveTillLayerConfiguration(Container expectedContainer) {
        super(Arrays.asList(expectedContainer));
    }

    @Override
    public boolean executedAsPlanned(List<Container> list) {
        List<Class<? extends DataContainer>> missingExpectedContainers =
            getContainerList().stream().map(DataContainer::getClass).collect(Collectors.toList());
        if (list != null) {
            list.forEach(receivedContainer -> missingExpectedContainers.remove(receivedContainer.getClass()));
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
