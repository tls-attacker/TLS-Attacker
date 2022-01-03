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

public class SpecificContainerLayerConfiguration<Container extends DataContainer>
    extends LayerConfiguration<Container> {

    public SpecificContainerLayerConfiguration(List<Container> containerList) {
        super(containerList);
    }

    public SpecificContainerLayerConfiguration(Container... containers) {
        super(containers);
    }

    @Override
    public boolean isFullfilled(List<Container> list) {
        // TODO Return true if the exact list of the configuration has been received
        return true;
    }

}
