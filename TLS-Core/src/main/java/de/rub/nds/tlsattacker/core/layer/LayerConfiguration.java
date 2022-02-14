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

/**
 * Contains a list of {@link DataContainer} with additional information about how to send and receive them
 * and whether they were sent/received correctly. See {@link SpecificContainerLayerConfiguration} and
 * {@link TillContainerLayerConfiguration} for implementations.
 * @param <Container>
 */
public abstract class LayerConfiguration<Container extends DataContainer> {

    private final List<Container> containerList;

    private List<DataContainerFilter> containerFilterList;

    private boolean allowTrailingContainers = false;

    private boolean processTrailingContainers = true;

    public LayerConfiguration(List<Container> containerList) {
        this.containerList = containerList;
    }

    public LayerConfiguration(Container... containers) {
        this.containerList = Arrays.asList(containers);
    }

    public List<Container> getContainerList() {
        return containerList;
    }

    public abstract boolean executedAsPlanned(List<Container> list);

    public abstract boolean failedEarly(List<Container> list);

    public boolean successRequiresMoreContainers(List<Container> list) {
        return !failedEarly(list) && !executedAsPlanned(list);
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

    public boolean isAllowTrailingContainers() {
        return allowTrailingContainers;
    }

    public void setAllowTrailingContainers(boolean allowTrailingContainers) {
        this.allowTrailingContainers = allowTrailingContainers;
    }

    public List<DataContainerFilter> getContainerFilterList() {
        return containerFilterList;
    }

    public void setContainerFilterList(List<DataContainerFilter> containerFilterList) {
        this.containerFilterList = containerFilterList;
    }

    public boolean isProcessTrailingContainers() {
        return processTrailingContainers;
    }

    public void setProcessTrailingContainers(boolean processTrailingContainers) {
        this.processTrailingContainers = processTrailingContainers;
    }
}
