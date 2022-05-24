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
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;

import java.util.LinkedList;
import java.util.List;

public class LayerProcessingResult<T extends DataContainer> {

    private List<T> usedContainers;

    // holds Exceptions that came up during layer parsing
    private final List<Exception> producedExceptions;

    // TODO: is this really necessary? I would guess that only bytes at the end can be dangling, because we parse from front to back
    private final byte[] danglingBytes;
    private LayerType layerType;
    private boolean executedAsPlanned;

    public LayerProcessingResult(List<T> usedContainers, LayerType layerType, boolean executedAsPlanned, List<Exception> producedExceptions, byte[] danglingBytes) {
        this.usedContainers = usedContainers;
        this.layerType = layerType;
        this.executedAsPlanned = executedAsPlanned;
        this.producedExceptions = producedExceptions;
        this.danglingBytes = danglingBytes;
    }

    public LayerProcessingResult(List<T> usedContainers, LayerType layerType, boolean executedAsPlanned, List<Exception> producedExceptions) {
        this.usedContainers = usedContainers;
        this.layerType = layerType;
        this.executedAsPlanned = executedAsPlanned;
        this.producedExceptions = producedExceptions;
        this.danglingBytes = new byte[]{};
    }

    public LayerProcessingResult(List<T> usedContainers, LayerType layerType, boolean executedAsPlanned, byte[] danglingBytes) {
        this.usedContainers = usedContainers;
        this.layerType = layerType;
        this.executedAsPlanned = executedAsPlanned;
        this.producedExceptions = new LinkedList<>();
        this.danglingBytes = danglingBytes;
    }

    public LayerProcessingResult(List<T> usedContainers, LayerType layerType, boolean executedAsPlanned) {
        this.usedContainers = usedContainers;
        this.layerType = layerType;
        this.executedAsPlanned = executedAsPlanned;
        this.producedExceptions = new LinkedList<>();
        this.danglingBytes = new byte[]{};
    }

    public List<T> getUsedContainers() {
        return usedContainers;
    }

    public void setUsedContainers(List<T> usedContainers) {
        this.usedContainers = usedContainers;
    }

    public LayerType getLayerType() {
        return layerType;
    }

    public boolean isExecutedAsPlanned() {
        return executedAsPlanned;
    }

    public void setExecutedAsPlanned(boolean executedAsPlanned) {
        this.executedAsPlanned = executedAsPlanned;
    }

    public void setLayerType(LayerType layerType) {
        this.layerType = layerType;
    }

    public List<Exception> getProducedExceptions() {
        return producedExceptions;
    }

    public byte[] getDanglingBytes() {
        return danglingBytes;
    }
}
