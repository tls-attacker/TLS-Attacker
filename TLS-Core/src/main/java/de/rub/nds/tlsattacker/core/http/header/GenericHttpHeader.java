/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.http.header;

import de.rub.nds.modifiablevariable.util.IllegalStringAdapter;
import de.rub.nds.tlsattacker.core.http.header.preparator.GenericHttpHeaderPreparator;
import de.rub.nds.tlsattacker.core.http.header.serializer.HttpHeaderSerializer;
import de.rub.nds.tlsattacker.core.layer.context.HttpContext;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.io.InputStream;

@XmlAccessorType(XmlAccessType.FIELD)
public class GenericHttpHeader extends HttpHeader {

    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String headerNameConfig;

    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String headerValueConfig;

    public GenericHttpHeader() {}

    public GenericHttpHeader(String headerNameConfig, String headerValueConfig) {
        this.headerNameConfig = headerNameConfig;
        this.headerValueConfig = headerValueConfig;
    }

    public String getHeaderNameConfig() {
        return headerNameConfig;
    }

    public void setHeaderNameConfig(String headerNameConfig) {
        this.headerNameConfig = headerNameConfig;
    }

    public String getHeaderValueConfig() {
        return headerValueConfig;
    }

    public void setHeaderValueConfig(String headerValueConfig) {
        this.headerValueConfig = headerValueConfig;
    }

    @Override
    public GenericHttpHeaderPreparator getPreparator(HttpContext httpContext) {
        return new GenericHttpHeaderPreparator(httpContext.getChooser(), this);
    }

    @Override
    public Parser<?> getParser(HttpContext context, InputStream stream) {
        return null; // TODO Parser is not used
    }

    @Override
    public Serializer<?> getSerializer(HttpContext context) {
        return new HttpHeaderSerializer(this);
    }

    @Override
    public Handler<?> getHandler(HttpContext context) {
        return null;
    }
}
