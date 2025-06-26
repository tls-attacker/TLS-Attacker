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

public class ReceiveTillLayerConfiguration<Container extends DataContainer>
        extends ReceiveLayerConfiguration<Container> {

    private boolean processTrailingContainers = true;

    private int maxNumberOfQuicPacketsToReceive;

    @SafeVarargs
    public ReceiveTillLayerConfiguration(LayerType layerType, Container... expectedContainers) {
        super(layerType, Arrays.asList(expectedContainers));
    }

    public ReceiveTillLayerConfiguration(LayerType layerType, List<Container> expectedContainers) {
        super(layerType, expectedContainers);
    }

    @SafeVarargs
    public ReceiveTillLayerConfiguration(
            LayerType layerType,
            boolean processTrailingContainers,
            Container... expectedContainers) {
        this(layerType, processTrailingContainers, Arrays.asList(expectedContainers));
    }

    public ReceiveTillLayerConfiguration(
            LayerType layerType,
            boolean processTrailingContainers,
            List<Container> expectedContainers) {
        super(layerType, expectedContainers);
        this.processTrailingContainers = processTrailingContainers;
    }

    @SafeVarargs
    public ReceiveTillLayerConfiguration(
            LayerType layerType,
            boolean processTrailingContainers,
            int maxNumberOfQuicPacketsToReceive,
            Container... expectedContainers) {
        this(
                layerType,
                processTrailingContainers,
                maxNumberOfQuicPacketsToReceive,
                Arrays.asList(expectedContainers));
    }

    public ReceiveTillLayerConfiguration(
            LayerType layerType,
            boolean processTrailingContainers,
            int maxNumberOfQuicPacketsToReceive,
            List<Container> expectedContainers) {
        this(layerType, processTrailingContainers, expectedContainers);
        this.maxNumberOfQuicPacketsToReceive = maxNumberOfQuicPacketsToReceive;
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
        // System.out.println("Checking if received containers match expected ones.");
        List<Class<? extends DataContainer>> missingExpectedContainers =
                getContainerList().stream()
                        .map(container -> (Class<? extends DataContainer>) container.getClass())
                        .collect(Collectors.toList());
        // Printing the expected containers for debugging purposes
        // if (getContainerList() != null) {
        //    getContainerList().forEach(
        //            container ->
        //                    System.out.println(
        //                            "Expected container: "
        //                                    + container.getClass().getSimpleName()));
        // }
        // for each container we received remove it from the expected ones to be left with any

        // additional containers
        if (list != null) {
            list.forEach(
                    receivedContainer ->
                            missingExpectedContainers.remove(receivedContainer.getClass()));
            // printing the received containers for debugging purposes
            // list.forEach(
            //        container ->
            //                System.out.println(
            //                        "Received container (inside shoudlcontinueProcessing of
            // ReceiveTillLayerConfiguration): "
            //                                + container.getClass().getSimpleName()));
        } //
        // printint the if the list of missing expected containers is empty
        if (!missingExpectedContainers.isEmpty()) {
            System.out.println("All expected containers were NOT received.");
        }
        return missingExpectedContainers.isEmpty();
    }

    @Override
    public boolean shouldContinueProcessing(
            List<Container> list, boolean receivedTimeout, boolean dataLeftToProcess) {
        if (receivedTimeout) {
            System.out.println(
                    "Received timeout, not continuing processing in ReceiveTillLayerConfiguration.");
            return false;
        } else {
            return !executedAsPlanned(list);
        }
    }

    public int getMaxNumberOfQuicPacketsToReceive() {
        return maxNumberOfQuicPacketsToReceive;
    }

    @Override
    public String toCompactString() {
        return "("
                + getLayerType().getName()
                + ") ReceiveTill:"
                + getContainerList().stream()
                        .map(DataContainer::toCompactString)
                        .collect(Collectors.joining(","));
    }

    @Override
    public boolean shouldBeLogged(Level level) {
        return true;
    }
}
