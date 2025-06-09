/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer;

import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.constant.LayerType;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAnyElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlSeeAlso;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Wrapper class for {@link LayerProcessingResult}. Makes results of multiple layers available for a
 * {@link LayerStack}.
 */
@XmlRootElement(name = "LayerStackProcessingResult")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlSeeAlso({ImplementedLayers.class})
public class LayerStackProcessingResult {

    private static final Logger LOGGER = LogManager.getLogger();

    private final List<LayerProcessingResult<?>> layerProcessingResultList;

    // whether any layer has unreadBytes
    private boolean hasUnreadBytes;

    @XmlAnyElement(lax = true)
    @XmlElementWrapper
    private final List<LayerType> layersWithUnreadBytes = new LinkedList<>();

    /** Private no-arg constructor to please JAXB */
    @SuppressWarnings("unused")
    private LayerStackProcessingResult() {
        layerProcessingResultList = null;
    }

    public LayerStackProcessingResult(List<LayerProcessingResult<?>> layerProcessingResultList) {
        this.layerProcessingResultList = layerProcessingResultList;
        for (LayerProcessingResult<?> layerProcessingResult : layerProcessingResultList) {
            if (layerProcessingResult.getUnreadBytes().length != 0) {
                layersWithUnreadBytes.add(layerProcessingResult.getLayerType());
                hasUnreadBytes = true;
            }
        }
    }

    public List<LayerProcessingResult<?>> getLayerProcessingResultList() {
        return layerProcessingResultList;
    }

    public LayerProcessingResult<?> getResultForLayer(LayerType layerType) {
        if (layerProcessingResultList != null) {
            for (LayerProcessingResult<?> layerResult : layerProcessingResultList) {
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

    public boolean executedAsPlanned() {
        for (LayerProcessingResult<?> result : layerProcessingResultList) {
            if (!result.isExecutedAsPlanned()) {
                LOGGER.warn(
                        "{} failed: Layer {}, did not execute as planned",
                        this.getClass().getSimpleName(),
                        result.getLayerType());
                return false;
            }
        }
        return true;
    }
}
