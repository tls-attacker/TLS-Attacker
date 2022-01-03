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

public class TillContainerLayerConfiguration<Container extends DataContainer> extends LayerConfiguration<Container> {

    @Override
    public boolean isFullfilled(List<Container> list) {
        // TODO check that this is fullfilled
        return true;
    }

}
