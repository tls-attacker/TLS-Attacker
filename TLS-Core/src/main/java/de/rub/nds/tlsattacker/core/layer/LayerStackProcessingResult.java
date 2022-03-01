/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.layer;

import de.rub.nds.tlsattacker.core.layer.constant.LayerType;
import java.util.List;

/**
 * Wrapper class for {@link LayerProcessingResult}. Makes results of multiple layers avilable for a {@link LayerStack}.
 */
public class LayerStackProcessingResult {

    private final List<LayerProcessingResult> layerProcessingResultList;

    public LayerStackProcessingResult(List<LayerProcessingResult> layerProcessingResultList) {
        this.layerProcessingResultList = layerProcessingResultList;
    }

    public List<LayerProcessingResult> getLayerProcessingResultList() {
        return layerProcessingResultList;
    }

    public LayerProcessingResult getResultForLayer(LayerType layerType) {
        if (layerProcessingResultList != null) {
            for (LayerProcessingResult layerResult : layerProcessingResultList) {
                if (layerResult.getLayerType().equals(layerType)) {
                    return layerResult;
                }
            }
        }
        return null;
    }
}
