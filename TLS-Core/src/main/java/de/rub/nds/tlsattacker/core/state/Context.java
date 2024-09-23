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
import de.rub.nds.tlsattacker.core.layer.LayerStack;
import de.rub.nds.tlsattacker.core.layer.LayerStackFactory;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.layer.context.HttpContext;
import de.rub.nds.tlsattacker.core.layer.context.TcpContext;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.core.workflow.chooser.ChooserFactory;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;

/**
 * Contains runtime information about a connection. With the introduction of the layer system all
 * layer-specific variables have been moved to the respective layer-context (e.g. {@link
 * HttpContext}.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class Context {

    /** TODO: Replace with standard values in layer contexts */
    private Chooser chooser;

    /** TODO: Replace with configs split by layer */
    private Config config;

    private TransportHandler transportHandler;

    private TcpContext tcpContext;

    private HttpContext httpContext;

    private TlsContext tlsContext;

    private QuicContext quicContext;

    private LayerStack layerStack;

    private ConnectionEndType talkingConnectionEndType = ConnectionEndType.CLIENT;

    /** The end point of the connection that this context represents. */
    private AliasedConnection connection;

    /** The state which this context belongs to */
    private State state;

    public Context(State state, AliasedConnection connection) {
        this.state = state;
        this.config = state.getConfig();
        this.chooser = ChooserFactory.getChooser(ChooserType.DEFAULT, this, config);
        this.connection = connection;
        prepareWithLayers(config.getDefaultLayerConfiguration());
    }

    public State getState() {
        return state;
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

    public void prepareWithLayers(StackConfiguration type) {
        tlsContext = new TlsContext(this);
        httpContext = new HttpContext(this);
        tcpContext = new TcpContext(this);
        quicContext = new QuicContext(this);
        layerStack = LayerStackFactory.createLayerStack(type, this);
        this.setLayerStack(layerStack);
    }

    public QuicContext getQuicContext() {
        return quicContext;
    }

    public void setQuicContext(QuicContext quicContext) {
        this.quicContext = quicContext;
    }
}
