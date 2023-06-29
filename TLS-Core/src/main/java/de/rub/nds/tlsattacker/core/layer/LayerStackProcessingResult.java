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
import java.util.LinkedList;
import java.util.List;

/**
 * Wrapper class for {@link LayerProcessingResult}. Makes results of multiple layers available for a
 * {@link LayerStack}.
 */
public class LayerStackProcessingResult {

    private final List<LayerProcessingResult> layerProcessingResultList;

    // whether any layer has unreadBytes
    private boolean hasUnreadBytes;

    private final List<LayerType> layersWithUnreadBytes = new LinkedList<>();

    public LayerStackProcessingResult(List<LayerProcessingResult> layerProcessingResultList) {
        this.layerProcessingResultList = layerProcessingResultList;
        for (LayerProcessingResult layerProcessingResult : layerProcessingResultList) {
            if (layerProcessingResult.getUnreadBytes().length != 0) {
                layersWithUnreadBytes.add(layerProcessingResult.getLayerType());
                hasUnreadBytes = true;
            }
        }
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

    public boolean hasUnreadBytes() {
        return hasUnreadBytes;
    }

    public List<LayerType> getLayersWithUnreadBytes() {
        return layersWithUnreadBytes;
    }
}
