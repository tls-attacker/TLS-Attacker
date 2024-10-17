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
import org.apache.logging.log4j.Level;

/**
 * Send configuration that sends a list of containers to the recipient.
 *
 * @param <Container>
 */
public class MissingSendLayerConfiguration<Container extends DataContainer<?>>
        extends LayerConfiguration<Container> {

    public MissingSendLayerConfiguration(LayerType layerType) {
        super(layerType, (List<Container>) null);
    }

    @Override
    public boolean executedAsPlanned(List<Container> list) {
        return true;
    }

    @Override
    public boolean failedEarly(List<Container> list) {
        return false;
    }

    @Override
    public String toCompactString() {
        return "(" + getLayerType().getName() + ") Not configured";
    }

    @Override
    public boolean shouldBeLogged(Level level) {
        return level.isMoreSpecificThan(Level.INFO); // DEBUG, TRACE etc should log it.
    }
}
