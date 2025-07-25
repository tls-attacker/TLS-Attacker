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
 * Send configuration that sends a list of containers to the recipient.
 *
 * @param <Container>
 */
public class SpecificSendLayerConfiguration<Container extends DataContainer>
        extends LayerConfiguration<Container> {

    public SpecificSendLayerConfiguration(LayerType layerType, List<Container> containerList) {
        super(layerType, containerList);
    }

    @SafeVarargs
    public SpecificSendLayerConfiguration(LayerType layerType, Container... containers) {
        super(layerType, containers);
    }

    /**
     * Tests if the SendConfiguration executed as planned. It compares the planned containers with
     * the actually sent containers. It passes if the configured amount of containers has been sent,
     * or if more than the configured amount has been sent. This is useful if the configured
     * containers are split up due to fragmentation.
     *
     * @param list The list executed DataContainers
     * @return true if at least all configured containers have been sent
     */
    @Override
    public boolean executedAsPlanned(List<Container> list) {
        if (list == null) {
            return false;
        }
        if (getContainerList() == null) {
            return true;
        }
        // sometimes more containers are sent than configured, if they are split up
        // this should not fail the SendAction
        return list.size() >= getContainerList().size();
    }

    @Override
    public boolean shouldContinueProcessing(
            List<Container> list, boolean receivedTimeout, boolean dataLeftToProcess) {
        throw new UnsupportedOperationException("This api does not make sense for send layers");
    }

    @Override
    public String toCompactString() {
        return "("
                + getLayerType().getName()
                + ") Send:"
                + getContainerList().stream()
                        .map(DataContainer::toCompactString)
                        .collect(Collectors.joining(","));
    }

    @Override
    public boolean shouldBeLogged(Level level) {
        return true;
    }
}
