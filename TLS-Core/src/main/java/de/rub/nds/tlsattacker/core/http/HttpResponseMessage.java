/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.http;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.http.header.*;
import de.rub.nds.tlsattacker.core.layer.DataContainer;
import de.rub.nds.tlsattacker.core.layer.context.HttpContext;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class HttpResponseMessage extends ModifiableVariableHolder
    implements DataContainer<HttpResponseMessage, HttpContext> {

    private ModifiableString responseProtocol;

    private ModifiableString responseStatusCode;

    private ModifiableString responseContent;
    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = GenericHttpHeader.class, name = "HttpHeader"),
        @XmlElement(type = ContentLengthHeader.class, name = "ContentLengthHeader"),
        @XmlElement(type = DateHeader.class, name = "DateHeader"),
        @XmlElement(type = ExpiresHeader.class, name = "ExpiresHeader"),
        @XmlElement(type = LocationHeader.class, name = "LocationHeader"),
        @XmlElement(type = HostHeader.class, name = "HostHeader"),
        @XmlElement(type = TokenBindingHeader.class, name = "TokenBindingHeader") })
    @HoldsModifiableVariable
    private List<HttpHeader> header;

    public HttpResponseMessage() {
        header = new LinkedList<>();
    }

    public HttpResponseMessage(Config config) {
        header = new LinkedList<>();
        header.add(new GenericHttpHeader("Content-Type", "text/html; charset=UTF-8"));
        header.add(new LocationHeader());
        header.add(new ContentLengthHeader());
        header.add(new DateHeader());
        header.add(new ExpiresHeader());
        header.add(new GenericHttpHeader("Cache-Control", "private, max-age=0"));
        header.add(new GenericHttpHeader("Server", "GSE"));
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

    public List<HttpHeader> getHeader() {
        return header;
    }

    public void setHeader(List<HttpHeader> header) {
        this.header = header;
    }

    public String toCompactString() {
        return "HttpResponseMessage";
    }

    public java.lang.String toShortString() {
        return "HTTP_RES";
    }

    @Override
    public HttpResponseHandler getHandler(HttpContext httpContext) {
        return new HttpResponseHandler();
    }

    public HttpResponseParser getParser(HttpContext context, InputStream stream) {
        return new HttpResponseParser(stream);
    }

    public HttpResponsePreparator getPreparator(HttpContext context) {
        return new HttpResponsePreparator(this);
    }

    public HttpResponseSerializer getSerializer(HttpContext context) {
        return new HttpResponseSerializer(this);
    }
}
