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

public abstract class LayerConfiguration<Container extends DataContainer> {

    private final List<Container> containerList;

    public LayerConfiguration(List<Container> containerList) {
        this.containerList = containerList;
    }

    public LayerConfiguration(Container... containers) {
        this.containerList = Arrays.asList(containers);
    }

    public List<Container> getContainerList() {
        return containerList;
    }

    public abstract boolean isFullfilled(List<Container> list);
}
