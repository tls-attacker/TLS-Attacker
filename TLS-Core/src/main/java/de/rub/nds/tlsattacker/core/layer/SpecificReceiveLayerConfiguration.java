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
import de.rub.nds.tlsattacker.core.state.Context;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.logging.log4j.Level;

/**
 * ReceiveConfiguration that receives a specific list of DataContainers. Any additional received
 * containers are marked as such.
 */
public class SpecificReceiveLayerConfiguration<Container extends DataContainer<Context>>
        extends ReceiveLayerConfiguration<Container> {

    public SpecificReceiveLayerConfiguration(LayerType layerType, List<Container> containerList) {
        super(layerType, containerList);
    }

    @SafeVarargs
    public SpecificReceiveLayerConfiguration(LayerType layerType, Container... containers) {
        super(layerType, containers);
    }

    @Override
    public boolean executedAsPlanned(List<Container> list) {
        return evaluateReceivedContainers(list, false);
    }

    /**
     * Compares the received DataContainers to the list of expected DataContainers. An expected
     * DataContainer may be skipped if it is not marked as required. An unexpected DataContainer may
     * be ignored if a DataContainerFilter applies.
     *
     * @param list The list of DataContainers
     * @param mayReceiveMoreContainers Determines if an incomplete result is acceptable. This is the
     *     case if no contradictory DataContainer has been received yet and the LayerConfiguration
     *     can be satisfied if additional DataContainers get provided
     */
    protected boolean evaluateReceivedContainers(
            List<Container> list, boolean mayReceiveMoreContainers) {
        if (list == null) {
            return false;
        }
        int j = 0;
        List<Container> expectedContainers = getContainerList();
        if (expectedContainers != null) {
            for (int i = 0; i < expectedContainers.size(); i++) {
                if (j >= list.size() && expectedContainers.get(i).isRequired()) {
                    return mayReceiveMoreContainers;
                } else if (j < list.size()) {
                    if (!expectedContainers.get(i).getClass().equals(list.get(j).getClass())
                            && expectedContainers.get(i).isRequired()) {
                        if (containerCanBeFiltered(list.get(j))) {
                            j++;
                            i--;
                        } else {
                            return false;
                        }

                    } else if (expectedContainers
                            .get(i)
                            .getClass()
                            .equals(list.get(j).getClass())) {
                        j++;
                    }
                }
            }

            for (; j < list.size(); j++) {
                if (!containerCanBeFiltered(list.get(j)) && !mayReceiveMoreContainers) {
                    return false;
                }
            }
        }
        return true;
    }

    public void setContainerFilterList(DataContainerFilter... containerFilters) {
        this.setContainerFilterList(Arrays.asList(containerFilters));
    }

    public boolean containerCanBeFiltered(Container container) {
        if (getContainerFilterList() != null) {
            for (DataContainerFilter containerFilter : getContainerFilterList()) {
                if (containerFilter.filterApplies(container)) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public boolean shouldContinueProcessing(
            List<Container> list, boolean receivedTimeout, boolean dataLeftToProcess) {
        if (receivedTimeout && !dataLeftToProcess) {
            return false;
        }
        if (dataLeftToProcess) {
            return true;
        }
        return !evaluateReceivedContainers(list, true);
    }

    @Override
    public String toCompactString() {
        return "("
                + getLayerType().getName()
                + ") Receive:"
                + getContainerList().stream()
                        .map(DataContainer::toCompactString)
                        .collect(Collectors.joining(","));
    }

    @Override
    public boolean shouldBeLogged(Level level) {
        return true;
    }
}
