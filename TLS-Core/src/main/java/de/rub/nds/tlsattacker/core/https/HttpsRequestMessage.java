/**
 * /**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.https;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.https.header.ContentLengthHeader;
import de.rub.nds.tlsattacker.core.https.header.CookieHeader;
import de.rub.nds.tlsattacker.core.https.header.DateHeader;
import de.rub.nds.tlsattacker.core.https.header.ExpiresHeader;
import de.rub.nds.tlsattacker.core.https.header.GenericHttpsHeader;
import de.rub.nds.tlsattacker.core.https.header.HostHeader;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsattacker.core.https.header.LocationHeader;
import de.rub.nds.tlsattacker.core.https.header.TokenBindingHeader;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlElements;

public class HttpsRequestMessage extends ProtocolMessage {

    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = GenericHttpsHeader.class, name = "HttpsHeader"),
            @XmlElement(type = ContentLengthHeader.class, name = "ContentLengthHeader"),
            @XmlElement(type = DateHeader.class, name = "DateHeader"),
            @XmlElement(type = ExpiresHeader.class, name = "ExpiresHeader"),
            @XmlElement(type = LocationHeader.class, name = "LocationHeader"),
            @XmlElement(type = HostHeader.class, name = "HostHeader"),
            @XmlElement(type = TokenBindingHeader.class, name = "TokenBindingHeader"),
            @XmlElement(type = TokenBindingHeader.class, name = "CookieHeader") })
    @HoldsModifiableVariable
    private List<HttpsHeader> header;

    private ModifiableString requestType;

    private ModifiableString requestPath;

    private ModifiableString requestProtocol;

    public HttpsRequestMessage() {
        super();
        protocolMessageType = ProtocolMessageType.APPLICATION_DATA;
        header = new LinkedList<>();
    }

    public HttpsRequestMessage(Config config) {
        super();
        protocolMessageType = ProtocolMessageType.APPLICATION_DATA;
        header = new LinkedList<>();
        header.add(new HostHeader());
        header.add(new GenericHttpsHeader("Connection", "keep-alive"));
        header.add(new GenericHttpsHeader("Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"));
        header.add(new GenericHttpsHeader("Accept-Encoding", "identity"));
        header.add(new GenericHttpsHeader("Accept-Language", "de-DE,de;q=0.8,en-US;q=0.6,en;q=0.4"));
        if (config.isAddTokenBindingExtension()) {
            header.add(new TokenBindingHeader());
        }
        if (config.isAddHttpsCookie()) {
            header.add(new CookieHeader());
        }
        header.add(new GenericHttpsHeader("Upgrade-Insecure-Requests", "1"));
        header.add(new GenericHttpsHeader(
                "User-Agent",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/59.0.3071.109 Chrome/59.0.3071.109 Safari/537.36"));
    }

    public List<HttpsHeader> getHeader() {
        return header;
    }

    public void setHeader(List<HttpsHeader> header) {
        this.header = header;
    }

    public ModifiableString getRequestType() {
        return requestType;
    }

    public void setRequestType(ModifiableString requestType) {
        this.requestType = requestType;
    }

    public void setRequestType(String requestType) {
        this.requestType = ModifiableVariableFactory.safelySetValue(this.requestType, requestType);
    }

    public ModifiableString getRequestPath() {
        return requestPath;
    }

    public void setRequestPath(ModifiableString requestPath) {
        this.requestPath = requestPath;
    }

    public void setRequestPath(String requestPath) {
        this.requestPath = ModifiableVariableFactory.safelySetValue(this.requestPath, requestPath);
    }

    public ModifiableString getRequestProtocol() {
        return requestProtocol;
    }

    public void setRequestProtocol(ModifiableString requestProtocol) {
        this.requestProtocol = requestProtocol;
    }

    public void setRequestProtocol(String requestProtocol) {
        this.requestProtocol = ModifiableVariableFactory.safelySetValue(this.requestProtocol, requestProtocol);
    }

    @Override
    public String toCompactString() {
        return "HttpsRequestMessage";
    }

    @Override
    public HttpsRequestHandler getHandler(TlsContext context) {
        return new HttpsRequestHandler(context);
    }

}
