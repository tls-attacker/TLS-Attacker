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
import org.apache.logging.log4j.Level;

/**
 * ReceiveConfiguration that receives a specific list of DataContainers. Any additional received
 * containers are marked as such.
 */
public class SpecificReceiveLayerConfiguration<Container extends DataContainer>
        extends ReceiveLayerConfiguration<Container> {

    protected enum ExecutionStatus {
        /** All containers were received as configured. */
        AS_PLANNED,
        /**
         * Thus far all received containers were expected, but some expected containers were not
         * (yet) received.
         */
        PENDING_MISSING_CONTAINERS,
        /** A container that was not expected was encountered. */
        UNEXPECTED_CONTAINER,
        /**
         * All expected containers were received, but also additional unexpected containers were
         * received afterwards.
         */
        ADDITIONAL_CONTAINERS;

        public boolean in(ExecutionStatus... statuses) {
            for (ExecutionStatus status : statuses) {
                if (this == status) {
                    return true;
                }
            }
            return false;
        }
    }

    public SpecificReceiveLayerConfiguration(LayerType layerType, List<Container> containerList) {
        super(layerType, containerList);
    }

    @SafeVarargs
    public SpecificReceiveLayerConfiguration(LayerType layerType, Container... containers) {
        super(layerType, containers);
    }

    @Override
    public boolean executedAsPlanned(List<Container> list) {
        return evaluateReceivedContainers(list) == ExecutionStatus.AS_PLANNED;
    }

    /**
     * Compares the received DataContainers to the list of expected DataContainers. An expected
     * DataContainer may be skipped if it is not marked as required. An unexpected DataContainer may
     * be ignored if a DataContainerFilter applies.
     *
     * @param receivedContainers The list of DataContainers
     */
    protected ExecutionStatus evaluateReceivedContainers(List<Container> receivedContainers) {
        if (receivedContainers == null) {
            return ExecutionStatus.PENDING_MISSING_CONTAINERS;
        }
        List<Container> expectedContainers = getContainerList();
        if (expectedContainers == null) {
            return ExecutionStatus.AS_PLANNED;
        }

        int i = 0;
        int j = 0;
        while (i < expectedContainers.size() && j < receivedContainers.size()) {
            var expected = expectedContainers.get(i);
            var received = receivedContainers.get(j);
            if (expected.getClass().equals(receivedContainers.get(j).getClass())) {
                // got an expected container -> increase reference
                i++;
                j++;
            } else if (expected.isRequired()) {
                if (!containerCanBeFiltered(received)) {
                    return ExecutionStatus.UNEXPECTED_CONTAINER;
                }
                // received something unexpected; but we can filter it
                j++;
            } else {
                // current message is not required - skip
                i++;
            }
        }

        if (i < expectedContainers.size()) {
            // we have not received all expected containers
            if (expectedContainers.subList(i, expectedContainers.size()).stream()
                    .anyMatch(DataContainer::isRequired)) {
                // and one of them is required
                return ExecutionStatus.PENDING_MISSING_CONTAINERS;
            }
        }

        // we got all required containers, check if there are unexpected trailing containers
        for (; j < receivedContainers.size(); j++) {
            if (!containerCanBeFiltered(receivedContainers.get(j))) {
                return ExecutionStatus.ADDITIONAL_CONTAINERS;
            }
        }

        return ExecutionStatus.AS_PLANNED;
    }

    /**
     * @deprecated Use {@link #evaluateReceivedContainers(List)} instead as its return value is more
     *     expressive.
     */
    @Deprecated(since = "2026-08-17")
    protected boolean evaluateReceivedContainers(
            List<Container> list, boolean mayReceiveMoreContainers) {
        var analysisResult = evaluateReceivedContainers(list);
        if (analysisResult.in(
                ExecutionStatus.ADDITIONAL_CONTAINERS,
                ExecutionStatus.PENDING_MISSING_CONTAINERS)) {
            return mayReceiveMoreContainers;
        }
        return analysisResult == ExecutionStatus.AS_PLANNED;
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
        return evaluateReceivedContainers(list) == ExecutionStatus.PENDING_MISSING_CONTAINERS;
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
