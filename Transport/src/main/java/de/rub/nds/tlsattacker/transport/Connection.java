/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.transport;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.Serializable;
import java.util.Objects;

@XmlTransient
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class Connection implements Serializable {

    protected Integer port = null;
    protected String ip = null;
    protected String ipv6 = null;
    protected String hostname = null;
    protected Integer proxyDataPort = null;
    protected String proxyDataHostname = null;
    protected Integer proxyControlPort = null;
    protected String proxyControlHostname = null;
    protected TransportHandlerType transportHandlerType = null;
    protected Integer timeout = null;
    protected Integer connectionTimeout = null;
    protected Integer sourcePort = null;
    protected Boolean useIpv6 = null;

    public Connection() {}

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
        ipv6 = other.ipv6;
        hostname = other.hostname;
        proxyDataPort = other.proxyDataPort;
        proxyDataHostname = other.proxyDataHostname;
        proxyControlPort = other.proxyControlPort;
        proxyControlHostname = other.proxyControlHostname;
        transportHandlerType = other.transportHandlerType;
        timeout = other.timeout;
        connectionTimeout = other.connectionTimeout;
        sourcePort = other.sourcePort;
        useIpv6 = other.useIpv6;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public String getIpv6() {
        return ipv6;
    }

    public void setIpv6(String ipv6) {
        this.ipv6 = ipv6;
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

    public Boolean getUseIpv6() {
        return useIpv6;
    }

    public void setUseIpv6(Boolean useIpv6) {
        this.useIpv6 = useIpv6;
    }

    /**
     * Get the connection end type of the connection end. This must be implemented by all children.
     *
     * @return the connection end type of the connection end.
     */
    public abstract ConnectionEndType getLocalConnectionEndType();

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        Connection that = (Connection) o;

        if (!Objects.equals(port, that.port)) {
            return false;
        }
        if (!Objects.equals(ip, that.ip)) {
            return false;
        }
        if (!Objects.equals(hostname, that.hostname)) {
            return false;
        }
        if (!Objects.equals(proxyDataPort, that.proxyDataPort)) {
            return false;
        }
        if (!Objects.equals(proxyDataHostname, that.proxyDataHostname)) {
            return false;
        }
        if (!Objects.equals(proxyControlPort, that.proxyControlPort)) {
            return false;
        }
        if (!Objects.equals(proxyControlHostname, that.proxyControlHostname)) {
            return false;
        }
        if (transportHandlerType != that.transportHandlerType) {
            return false;
        }
        if (!Objects.equals(timeout, that.timeout)) {
            return false;
        }
        if (!Objects.equals(connectionTimeout, that.connectionTimeout)) {
            return false;
        }
        if (!Objects.equals(sourcePort, that.sourcePort)) {
            return false;
        }
        return Objects.equals(useIpv6, that.useIpv6);
    }

    @Override
    public int hashCode() {
        int result = port != null ? port.hashCode() : 0;
        result = 31 * result + (ip != null ? ip.hashCode() : 0);
        result = 31 * result + (ipv6 != null ? ipv6.hashCode() : 0);
        result = 31 * result + (hostname != null ? hostname.hashCode() : 0);
        result = 31 * result + (proxyDataPort != null ? proxyDataPort.hashCode() : 0);
        result = 31 * result + (proxyDataHostname != null ? proxyDataHostname.hashCode() : 0);
        result = 31 * result + (proxyControlPort != null ? proxyControlPort.hashCode() : 0);
        result = 31 * result + (proxyControlHostname != null ? proxyControlHostname.hashCode() : 0);
        result = 31 * result + (transportHandlerType != null ? transportHandlerType.hashCode() : 0);
        result = 31 * result + (timeout != null ? timeout.hashCode() : 0);
        result = 31 * result + (connectionTimeout != null ? connectionTimeout.hashCode() : 0);
        result = 31 * result + (sourcePort != null ? sourcePort.hashCode() : 0);
        result = 31 * result + (useIpv6 != null ? useIpv6.hashCode() : 0);
        return result;
    }

    protected void addProperties(StringBuilder sb) {
        sb.append("host=").append(hostname);
        sb.append(" ip=").append(ip);
        sb.append(" ipv6=").append(ipv6);
        sb.append(" port=").append(port);
        sb.append(" proxyDataHost=").append(proxyDataHostname);
        sb.append(" proxyDataPort=").append(proxyDataPort);
        sb.append(" proxyControlHost=").append(proxyControlHostname);
        sb.append(" proxyControlPort=").append(proxyControlPort);
        sb.append(" type=").append(transportHandlerType);
        sb.append(" timeout=").append(timeout);
        sb.append(" connectionTimeout=").append(connectionTimeout);
        sb.append(" sourcePort=").append(sourcePort);
        sb.append(" useIpv6=").append(useIpv6);
    }

    protected void addCompactProperties(StringBuilder sb) {
        sb.append(hostname).append(":").append(port);
    }
}
