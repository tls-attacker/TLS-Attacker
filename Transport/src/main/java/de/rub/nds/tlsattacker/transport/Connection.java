/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
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
    protected String hostname = null;
    protected Integer proxyDataPort = null;
    protected String proxyDataHostname = null;
    protected Integer proxyControlPort = null;
    protected String proxyControlHostname = null;
    protected TransportHandlerType transportHandlerType = null;
    protected Integer timeout = null;

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
        hostname = other.hostname;
        proxyDataPort = other.proxyDataPort;
        proxyDataHostname = other.proxyDataHostname;
        proxyControlPort = other.proxyControlPort;
        proxyControlHostname = other.proxyControlHostname;
        transportHandlerType = other.transportHandlerType;
        timeout = other.timeout;
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

    /**
     * Get the connection end type of the connection end. This must be
     * implemented by all children.
     *
     * @return the connection end type of the connection end.
     */
    public abstract ConnectionEndType getLocalConnectionEndType();

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 41 * hash + Objects.hashCode(this.port);
        hash = 41 * hash + Objects.hashCode(this.transportHandlerType);
        hash = 41 * hash + Objects.hashCode(this.timeout);
        hash = 41 * hash + Objects.hashCode(this.getLocalConnectionEndType());
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
        if (!Objects.equals(this.port, other.port)) {
            return false;
        }
        if (this.transportHandlerType != other.transportHandlerType) {
            return false;
        }
        if (!Objects.equals(this.timeout, other.timeout)) {
            return false;
        }
        return Objects.equals(this.getLocalConnectionEndType(), other.getLocalConnectionEndType());
    }
}
