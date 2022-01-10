/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.state;


import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.layer.context.HttpContext;
import de.rub.nds.tlsattacker.core.layer.context.MessageContext;
import de.rub.nds.tlsattacker.core.layer.context.RecordContext;
import de.rub.nds.tlsattacker.core.layer.context.TcpContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlAccessorType(XmlAccessType.FIELD)
public class Context {

    private static final Logger LOGGER = LogManager.getLogger();

    TcpContext tcpContext;

    HttpContext httpContext;

    RecordContext recordContext;

    MessageContext messageContext;

    /**
     * Not bound to a layer, so it makes sense to save it here
     */
    private ConnectionEndType talkingConnectionEndType = ConnectionEndType.CLIENT;

    /**
     * The end point of the connection that this context represents.
     */
    private AliasedConnection connection;


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

    public RecordContext getRecordContext() {
        return recordContext;
    }

    public void setRecordContext(RecordContext recordContext) {
        this.recordContext = recordContext;
    }

    public MessageContext getMessageContext() {
        return messageContext;
    }

    public void setMessageContext(MessageContext messageContext) {
        this.messageContext = messageContext;
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

}
