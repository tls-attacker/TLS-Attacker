/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer;

import de.rub.nds.modifiablevariable.util.UnformattedByteArrayAdapter;
import de.rub.nds.tlsattacker.core.layer.constant.LayerType;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAnyElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.util.List;
import java.util.StringJoiner;

/**
 * Contains information about a layers actions, both after sending and receiving data.
 *
 * @param <Container>
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class LayerProcessingResult<Container extends DataContainer> {

    /** List of containers that were sent or received */
    @XmlAnyElement(lax = true)
    private List<Container> usedContainers;

    /** Type of layer that produced this result. */
    @XmlAnyElement(lax = true)
    private LayerType layerType;

    /** Whether the layer could send or receive bytes as planned. */
    private boolean executedAsPlanned;

    // holds any bytes which are unread in the layer after parsing
    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] unreadBytes;

    private LayerProcessingResult() {
        // JAXB needs this
    }

    public LayerProcessingResult(
            List<Container> usedContainers,
            LayerType layerType,
            boolean executedAsPlanned,
            byte[] unreadBytes) {
        this.usedContainers = usedContainers;
        this.layerType = layerType;
        this.executedAsPlanned = executedAsPlanned;
        this.unreadBytes = unreadBytes;
    }

    public LayerProcessingResult(
            List<Container> usedContainers, LayerType layerType, boolean executedAsPlanned) {
        this.usedContainers = usedContainers;
        this.layerType = layerType;
        this.executedAsPlanned = executedAsPlanned;
        this.unreadBytes = new byte[0];
    }

    public List<Container> getUsedContainers() {
        return usedContainers;
    }

    public void setUsedContainers(List<Container> usedContainers) {
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

    public byte[] getUnreadBytes() {
        return unreadBytes;
    }

    public void setUnreadBytes(byte[] unreadBytes) {
        this.unreadBytes = unreadBytes;
    }

    public String toCompactString() {
        StringBuilder sb = new StringBuilder();
        sb.append("LayerType: ");
        sb.append(layerType);
        sb.append(" As Planned: ");
        sb.append(executedAsPlanned);
        sb.append(" Containers: ");
        StringJoiner joiner = new StringJoiner(", ");
        for (Container container : usedContainers) {
            joiner.add(container.toCompactString());
        }
        sb.append(joiner.toString());
        sb.append(" UnreadBytes: ");
        sb.append(unreadBytes.length);
        return sb.toString();
    }
}
