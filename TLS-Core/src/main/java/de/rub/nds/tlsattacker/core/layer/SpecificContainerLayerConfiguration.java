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

    /**
     * Determines if the LayerConfiguration, based on the final list of DataContainers, is satisfied
     * 
     * @param  list
     *              The list of DataContainers
     * @return      The final evaluation result
     */
    @Override
    public boolean executedAsPlanned(List<Container> list) {
        return evaluateContainers(list, false);
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
    private boolean evaluateContainers(List<Container> list, boolean mayReceiveMoreContainers) {
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

    /**
     * Determines if the LayerConfiguration, based on the current list of DataContainers, can possibly still be
     * satisfied
     * 
     * @param  list
     *              The list of DataContainers
     * @return      The evaluation result based on the current DataContainers
     */
    @Override
    public boolean failedEarly(List<Container> list) {
        return !evaluateContainers(list, true);
    }

}
