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

public class SpecificReceiveLayerConfiguration<Container extends DataContainer> extends LayerConfiguration<Container> {

    private List<DataContainerFilter> containerFilterList;

    private boolean allowTrailingContainers = false;

    private boolean processTrailingContainers = true;

    public SpecificReceiveLayerConfiguration(List<Container> containerList) {
        super(containerList);
    }

    public SpecificReceiveLayerConfiguration(Container... containers) {
        super(containers);
    }

    @Override
    public boolean executedAsPlanned(List<Container> list) {
        return evaluateReceivedContainers(list, false);
    }

    /**
     * Compares the received DataContainers to the list of expected DataContainers. An expected DataContainer may be
     * skipped if it is not marked as required. An unexpected DataContainer may be ignored if a DataContainerFilter
     * applies.
     *
     * @param list
     *                                 The list of DataContainers
     * @param mayReceiveMoreContainers
     *                                 Determines if an incomplete result is acceptable. This is the case if no
     *                                 contradictory DataContainer has been received yet and the LayerConfiguration can
     *                                 be satisfied if additional DataContainers get provided
     */
    private boolean evaluateReceivedContainers(List<Container> list, boolean mayReceiveMoreContainers) {
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

                    } else if (expectedContainers.get(i).getClass().equals(list.get(j).getClass())) {
                        j++;
                    }
                }
            }

            for (; j < list.size(); j++) {
                if (!containerCanBeFiltered(list.get(j)) && !isAllowTrailingContainers()) {
                    return false;
                }
            }
        }
        return true;
    }

    @Override
    public boolean failedEarly(List<Container> list) {
        return !evaluateReceivedContainers(list, true);
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
