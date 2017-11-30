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

public class HttpsResponseMessage extends ProtocolMessage {

    private ModifiableString responseProtocol;

    private ModifiableString responseStatusCode;

    private ModifiableString responseContent;
    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = GenericHttpsHeader.class, name = "HttpsHeader"),
            @XmlElement(type = ContentLengthHeader.class, name = "ContentLengthHeader"),
            @XmlElement(type = DateHeader.class, name = "DateHeader"),
            @XmlElement(type = ExpiresHeader.class, name = "ExpiresHeader"),
            @XmlElement(type = LocationHeader.class, name = "LocationHeader"),
            @XmlElement(type = HostHeader.class, name = "HostHeader"),
            @XmlElement(type = TokenBindingHeader.class, name = "TokenBindingHeader") })
    @HoldsModifiableVariable
    private List<HttpsHeader> header;

    public HttpsResponseMessage() {
        protocolMessageType = ProtocolMessageType.APPLICATION_DATA;
        header = new LinkedList<>();
    }

    public HttpsResponseMessage(Config config) {
        protocolMessageType = ProtocolMessageType.APPLICATION_DATA;
        header = new LinkedList<>();
        header.add(new GenericHttpsHeader("Content-Type", "text/html; charset=UTF-8"));
        header.add(new LocationHeader());
        header.add(new ContentLengthHeader());
        header.add(new DateHeader());
        header.add(new ExpiresHeader());
        header.add(new GenericHttpsHeader("Cache-Control", "private, max-age=0"));
        header.add(new GenericHttpsHeader("Server", "GSE"));
    }

    public ModifiableString getResponseProtocol() {
        return responseProtocol;
    }

    public void setResponseProtocol(ModifiableString responseProtocol) {
        this.responseProtocol = responseProtocol;
    }

    public void setResponseProtocol(String responseProtocol) {
        this.responseProtocol = ModifiableVariableFactory.safelySetValue(this.responseProtocol, responseProtocol);
    }

    public ModifiableString getResponseStatusCode() {
        return responseStatusCode;
    }

    public void setResponseStatusCode(ModifiableString responseStatusCode) {
        this.responseStatusCode = responseStatusCode;
    }

    public void setResponseStatusCode(String responseStatusCode) {
        this.responseStatusCode = ModifiableVariableFactory.safelySetValue(this.responseStatusCode, responseStatusCode);
    }

    public ModifiableString getResponseContent() {
        return responseContent;
    }

    public void setResponseContent(ModifiableString responseContent) {
        this.responseContent = responseContent;
    }

    public void setResponseContent(String responseContent) {
        this.responseContent = ModifiableVariableFactory.safelySetValue(this.responseContent, responseContent);
    }

    public List<HttpsHeader> getHeader() {
        return header;
    }

    public void setHeader(List<HttpsHeader> header) {
        this.header = header;
    }

    @Override
    public String toCompactString() {
        return "HttpsResponseMessage";
    }

    @Override
    public HttpsResponseHandler getHandler(TlsContext context) {
        return new HttpsResponseHandler(context);
    }

}
