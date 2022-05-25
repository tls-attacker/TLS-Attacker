/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.transport;

import java.io.Serializable;
import java.util.Objects;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlTransient;

@XmlTransient
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class Connection implements Serializable {

    protected Integer port = null;
    protected String ip = null;
    protected String hostname = null;
    protected Integer proxyDataPort = null;
    protected String proxyDataHostname = null;
    protected Integer proxyControlPort = null;
    protected String proxyControlHostname = null;
    protected TransportHandlerType transportHandlerType = null;
    protected Integer timeout = null;
    protected Integer firstTimeout = null;
    protected Integer connectionTimeout = null;
    protected Integer sourcePort = null;

    public Connection() {
    }

    public Connection(Integer port) {
        this.port = port;
    }

    public Connection(Integer port, String hostname) {
        this.port = port;
        this.hostname = hostname;
    }

    public Connection(Connection other) {
        port = other.port;
        ip = other.ip;
        hostname = other.hostname;
        proxyDataPort = other.proxyDataPort;
        proxyDataHostname = other.proxyDataHostname;
        proxyControlPort = other.proxyControlPort;
        proxyControlHostname = other.proxyControlHostname;
        transportHandlerType = other.transportHandlerType;
        timeout = other.timeout;
        firstTimeout = other.firstTimeout;
        connectionTimeout = other.connectionTimeout;
        sourcePort = other.sourcePort;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public Integer getPort() {
        return port;
    }

    public void setPort(Integer port) {
        this.port = port;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public Integer getProxyDataPort() {
        return proxyDataPort;
    }

    public void setProxyDataPort(Integer proxyDataPort) {
        this.proxyDataPort = proxyDataPort;
    }

    public String getProxyDataHostname() {
        return proxyDataHostname;
    }

    public void setProxyDataHostname(String proxyDataHostname) {
        this.proxyDataHostname = proxyDataHostname;
    }

    public String getProxyControlHostname() {
        return proxyControlHostname;
    }

    public void setProxyControlHostname(String proxyControlHostname) {
        this.proxyControlHostname = proxyControlHostname;
    }

    public Integer getProxyControlPort() {
        return proxyControlPort;
    }

    public void setProxyControlPort(Integer proxyControlPort) {
        this.proxyControlPort = proxyControlPort;
    }

    public void setTransportHandlerType(TransportHandlerType transportHandlerType) {
        this.transportHandlerType = transportHandlerType;
    }

    public TransportHandlerType getTransportHandlerType() {
        return transportHandlerType;
    }

    public void setTimeout(Integer timeout) {
        this.timeout = timeout;
    }

    public Integer getTimeout() {
        return timeout;
    }

    public void setFirstTimeout(Integer firstTimeout) {
        this.firstTimeout = firstTimeout;
    }

    public Integer getFirstTimeout() {
        return firstTimeout;
    }

    public Integer getConnectionTimeout() {
        return connectionTimeout;
    }

    public void setConnectionTimeout(Integer connectionTimeout) {
        this.connectionTimeout = connectionTimeout;
    }

    public Integer getSourcePort() {
        return sourcePort;
    }

    public void setSourcePort(Integer sourcePort) {
        this.sourcePort = sourcePort;
    }

    /**
     * Get the connection end type of the connection end. This must be implemented by all children.
     *
     * @return the connection end type of the connection end.
     */
    public abstract ConnectionEndType getLocalConnectionEndType();

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 83 * hash + Objects.hashCode(this.port);
        hash = 83 * hash + Objects.hashCode(this.ip);
        hash = 83 * hash + Objects.hashCode(this.hostname);
        hash = 83 * hash + Objects.hashCode(this.proxyDataPort);
        hash = 83 * hash + Objects.hashCode(this.proxyDataHostname);
        hash = 83 * hash + Objects.hashCode(this.proxyControlPort);
        hash = 83 * hash + Objects.hashCode(this.proxyControlHostname);
        hash = 83 * hash + Objects.hashCode(this.transportHandlerType);
        hash = 83 * hash + Objects.hashCode(this.timeout);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Connection other = (Connection) obj;
        if (!Objects.equals(this.ip, other.ip)) {
            return false;
        }
        if (!Objects.equals(this.hostname, other.hostname)) {
            return false;
        }
        if (!Objects.equals(this.proxyDataHostname, other.proxyDataHostname)) {
            return false;
        }
        if (!Objects.equals(this.proxyControlHostname, other.proxyControlHostname)) {
            return false;
        }
        if (!Objects.equals(this.port, other.port)) {
            return false;
        }
        if (!Objects.equals(this.proxyDataPort, other.proxyDataPort)) {
            return false;
        }
        if (!Objects.equals(this.proxyControlPort, other.proxyControlPort)) {
            return false;
        }
        if (this.transportHandlerType != other.transportHandlerType) {
            return false;
        }
        if (!Objects.equals(this.timeout, other.timeout)) {
            return false;
        }
        return true;
    }

    protected void addProperties(StringBuilder sb) {
        sb.append("host=").append(hostname);
        sb.append(" port=").append(port);
        sb.append(" proxyDataHost=").append(proxyDataHostname);
        sb.append(" proxyDataPort=").append(proxyDataPort);
        sb.append(" proxyControlHost=").append(proxyControlHostname);
        sb.append(" proxyControlPort=").append(proxyControlPort);
        sb.append(" type=").append(transportHandlerType);
        sb.append(" firstTimeout=").append(firstTimeout);
        sb.append(" timeout=").append(timeout);
    }

    protected void addCompactProperties(StringBuilder sb) {
        sb.append(hostname).append(":").append(port);
    }
}
