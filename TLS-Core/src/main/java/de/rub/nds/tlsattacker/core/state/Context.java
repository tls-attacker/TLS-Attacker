/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.state;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.constants.ChooserType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.layer.LayerStack;
import de.rub.nds.tlsattacker.core.layer.LayerStackFactory;
import de.rub.nds.tlsattacker.core.layer.constant.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.context.HttpContext;
import de.rub.nds.tlsattacker.core.layer.context.TcpContext;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.core.workflow.chooser.ChooserFactory;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Contains runtime information about a connection. With the introduction of the layer system all
 * layer-specific variables have been moved to the respective layer-context (e.g. {@link
 * HttpContext}.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class Context {

    private static final Logger LOGGER = LogManager.getLogger();

    /** TODO: Replace with standard values in layer contexts */
    private Chooser chooser;

    /** TODO: Replace with configs split by layer */
    private Config config;

    private TransportHandler transportHandler;

    private TcpContext tcpContext;

    private HttpContext httpContext;

    private TlsContext tlsContext;

    private LayerStack layerStack;

    private ConnectionEndType talkingConnectionEndType = ConnectionEndType.CLIENT;

    /** The end point of the connection that this context represents. */
    private AliasedConnection connection;

    public Context(Config config) {
        this.chooser = ChooserFactory.getChooser(ChooserType.DEFAULT, this, config);
        this.config = config;
        RunningModeType mode = config.getDefaultRunningMode();
        if (null == mode) {
            throw new ConfigurationException("Cannot create connection, running mode not set");
        } else {
            switch (mode) {
                case CLIENT:
                    this.connection = config.getDefaultClientConnection();
                    break;
                case SERVER:
                    this.connection = config.getDefaultServerConnection();
                    break;
                default:
                    throw new ConfigurationException(
                            "Cannot create connection for unknown running mode "
                                    + "'"
                                    + mode
                                    + "'");
            }
        }
        prepareWithLayers(config.getDefaultLayerConfiguration());
    }

    public Context(Config config, AliasedConnection connection) {
        this.chooser = ChooserFactory.getChooser(ChooserType.DEFAULT, this, config);
        this.config = config;
        this.connection = connection;
        prepareWithLayers(config.getDefaultLayerConfiguration());
    }

    public TcpContext getTcpContext() {
        return tcpContext;
    }

    public void setTcpContext(TcpContext tcpContext) {
        this.tcpContext = tcpContext;
    }

    public HttpContext getHttpContext() {
        return httpContext;
    }

    public void setHttpContext(HttpContext httpContext) {
        this.httpContext = httpContext;
    }

    public TlsContext getTlsContext() {
        return tlsContext;
    }

    public void setRecordContext(TlsContext tlsContext) {
        this.tlsContext = tlsContext;
    }

    public ConnectionEndType getTalkingConnectionEndType() {
        return talkingConnectionEndType;
    }

    public void setTalkingConnectionEndType(ConnectionEndType talkingConnectionEndType) {
        this.talkingConnectionEndType = talkingConnectionEndType;
    }

    public AliasedConnection getConnection() {
        return connection;
    }

    public void setConnection(AliasedConnection connection) {
        this.connection = connection;
    }

    public Chooser getChooser() {
        return chooser;
    }

    public void setChooser(Chooser chooser) {
        this.chooser = chooser;
    }

    public Config getConfig() {
        return config;
    }

    public void setConfig(Config config) {
        this.config = config;
    }

    public LayerStack getLayerStack() {
        return layerStack;
    }

    public void setLayerStack(LayerStack layerStack) {
        this.layerStack = layerStack;
    }

    public TransportHandler getTransportHandler() {
        return transportHandler;
    }

    public void setTransportHandler(TransportHandler transportHandler) {
        this.transportHandler = transportHandler;
    }

    @Override
    public String toString() {
        StringBuilder info = new StringBuilder();
        if (connection == null) {
            info.append("Context{ (no connection set) }");
        } else {
            info.append("Context{'").append(connection.getAlias()).append("'");
            if (connection.getLocalConnectionEndType() == ConnectionEndType.SERVER) {
                info.append(", listening on port ").append(connection.getPort());
            } else {
                info.append(", connected to ")
                        .append(connection.getHostname())
                        .append(":")
                        .append(connection.getPort());
            }
            info.append("}");
        }
        return info.toString();
    }

    public void setTlsContext(TlsContext tlsContext) {
        this.tlsContext = tlsContext;
    }

    public void prepareWithLayers(LayerConfiguration type) {
        tlsContext = new TlsContext(this);
        httpContext = new HttpContext(this);
        tcpContext = new TcpContext(this);
        layerStack = LayerStackFactory.createLayerStack(type, this);
        this.setLayerStack(layerStack);
    }
}
