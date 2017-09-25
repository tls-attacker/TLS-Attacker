/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport;

import java.util.Objects;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlTransient;

/**
 *
 * @author Lucas Hartmann <lucas.hartmann@rub.de>
 */
@XmlTransient
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class ConnectionEnd {

    protected String alias = null;
    protected Integer port = null;

    /**
     * Enable us to dynamically set a "hidden" default TansportHandlerType. This
     * rather unfortunate setup is needed to give the connection end a default
     * TransportHandlerType that won't appear in JAXB serialization.
     */
    @XmlTransient
    protected TransportHandlerType defaultTransportHandlerType = TransportHandlerType.TCP;

    /**
     * TansportHandlerType of this connection end. If null this will
     */
    protected TransportHandlerType transportHandlerType = null;

    /**
     * Enable us to dynamically set a "hidden" default timeout. This rather
     * unfortunate setup is needed to give the connection end a default timeout
     * that won't appear in JAXB serialization.
     */
    @XmlTransient
    protected Integer defaultTimeout = 1000;
    protected Integer timeout = null;

    public ConnectionEnd() {
    }

    public ConnectionEnd(String alias) {
        this.alias = alias;
    }

    public ConnectionEnd(String alias, Integer port) {
        this.alias = alias;
        this.port = port;
    }

    public ConnectionEnd(ConnectionEnd other) {
        alias = other.alias;
        port = other.port;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public Integer getPort() {
        return port;
    }

    public void setPort(Integer port) {
        this.port = port;
    }

    public TransportHandlerType getTransportHandlerType() {
        if (transportHandlerType != null) {
            return transportHandlerType;
        }
        return defaultTransportHandlerType;
    }

    public void setTransportHandlerType(TransportHandlerType transportHandlerType) {
        this.transportHandlerType = transportHandlerType;
    }

    /**
     * Change the default transportHandlerType. This value takes only effect if
     * transportHandlerType is not set (i.e. null). This value won't appear in
     * serialization output and won't be restored on un-marshaling. The user
     * needs to make sure that this value is set again after un-marshaling.
     * 
     * @param defaultTimeout
     */
    public void setDefaultTransportHandlerType(TransportHandlerType defaultTransportHandlerType) {
        this.defaultTransportHandlerType = defaultTransportHandlerType;
    }

    public void setTimeout(Integer timeout) {
        this.timeout = timeout;
    }

    public Integer getTimeout() {
        if (timeout != null) {
            return timeout;
        }
        return defaultTimeout;
    }

    /**
     * Change the default timeout. This value takes only effect if timeout is
     * not set (i.e. null). This value won't appear in serialization output and
     * won't be restored on un-marshaling. The user needs to make sure that this
     * value is set again after un-marshaling.
     */
    public void setDefaultTimeout(Integer defaultTimeout) {
        this.defaultTimeout = defaultTimeout;
    }

    /**
     * Get the connection end type of the connection end. This must be
     * implemented by all children.
     * 
     * @return the connection end type of the connection end.
     */
    public abstract ConnectionEndType getConnectionEndType();

    /**
     * Get the hostname of the connection end. This can be implemented by
     * children if it makes sense for the particular connection end type.
     */
    public abstract String getHostname();

    /**
     * Set the hostname of the connection end. This can be implemented by
     * children if it makes sense for the particular connection end type.
     */
    public abstract void setHostname(String hostname);

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 41 * hash + Objects.hashCode(this.alias);
        hash = 41 * hash + Objects.hashCode(this.port);
        hash = 41 * hash + Objects.hashCode(this.defaultTransportHandlerType);
        hash = 41 * hash + Objects.hashCode(this.transportHandlerType);
        hash = 41 * hash + Objects.hashCode(this.defaultTimeout);
        hash = 41 * hash + Objects.hashCode(this.timeout);
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
        final ConnectionEnd other = (ConnectionEnd) obj;
        if (!Objects.equals(this.alias, other.alias)) {
            return false;
        }
        if (!Objects.equals(this.port, other.port)) {
            return false;
        }
        if (this.defaultTransportHandlerType != other.defaultTransportHandlerType) {
            return false;
        }
        if (this.transportHandlerType != other.transportHandlerType) {
            return false;
        }
        if (!Objects.equals(this.defaultTimeout, other.defaultTimeout)) {
            return false;
        }
        if (!Objects.equals(this.timeout, other.timeout)) {
            return false;
        }
        return true;
    }

}
