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

    @Override
    public boolean executedAsPlanned(List<Container> list) {
        return evaluateContainers(list, false);
    }

    private boolean evaluateContainers(List<Container> list, boolean mightStillReceiveMissing) {
        if (list == null) {
            return false;
        }
        int j = 0;
        List<Container> expectedContainers = getContainerList();
        for (int i = 0; i < expectedContainers.size(); i++) {
            if (j >= list.size() && expectedContainers.get(i).isRequired()) {
                return mightStillReceiveMissing;
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

        return true;
    }

    @Override
    public boolean failedEarly(List<Container> list) {
        return evaluateContainers(list, true);
    }

}
