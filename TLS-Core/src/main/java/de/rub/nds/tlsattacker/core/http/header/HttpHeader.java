/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.http.header;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.tlsattacker.core.http.header.handler.HttpHeaderHandler;
import de.rub.nds.tlsattacker.core.layer.context.HttpContext;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import java.io.Serializable;

public abstract class HttpHeader extends ModifiableVariableHolder implements Serializable {

    protected ModifiableString headerName;

    protected ModifiableString headerValue;

    public HttpHeader() {}

    public ModifiableString getHeaderName() {
        return headerName;
    }

    public void setHeaderName(ModifiableString headerName) {
        this.headerName = headerName;
    }

    public void setHeaderName(String headerName) {
        this.headerName = ModifiableVariableFactory.safelySetValue(this.headerName, headerName);
    }

    public ModifiableString getHeaderValue() {
        return headerValue;
    }

    public void setHeaderValue(ModifiableString headerValue) {
        this.headerValue = headerValue;
    }

    public void setHeaderValue(String headerValue) {
        this.headerValue = ModifiableVariableFactory.safelySetValue(this.headerValue, headerValue);
    }

    public abstract Preparator getPreparator(HttpContext httpContext);

    public HttpHeaderHandler getHandler() {
        return null;
    }
}
