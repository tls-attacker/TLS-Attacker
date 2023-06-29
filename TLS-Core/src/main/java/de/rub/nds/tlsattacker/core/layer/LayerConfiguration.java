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

/**
 * Contains a list of {@link DataContainer} with additional information about how to send and
 * receive them and whether they were sent/received correctly.
 *
 * @param <Container>
 */
public abstract class LayerConfiguration<Container extends DataContainer> {

    private final List<Container> containerList;

    private final LayerType layerType;

    public LayerConfiguration(LayerType layerType, List<Container> containerList) {
        this.containerList = containerList;
        this.layerType = layerType;
    }

    public LayerConfiguration(LayerType layerType, Container... containers) {
        this.containerList = Arrays.asList(containers);
        this.layerType = layerType;
    }

    public List<Container> getContainerList() {
        return containerList;
    }

    /**
     * Determines if the LayerConfiguration, based on the final list of DataContainers, is satisfied
     *
     * @param list The list of DataContainers
     * @return The final evaluation result
     */
    public abstract boolean executedAsPlanned(List<Container> list);

    /**
     * Determines if the LayerConfiguration, based on the current list of DataContainers, can
     * possibly still be satisfied
     *
     * @param list The list of DataContainers
     * @return The evaluation result based on the current DataContainers
     */
    public abstract boolean failedEarly(List<Container> list);

    public boolean successRequiresMoreContainers(List<Container> list) {
        return !failedEarly(list) && !executedAsPlanned(list);
    }

    public LayerType getLayerType() {
        return layerType;
    }
}
