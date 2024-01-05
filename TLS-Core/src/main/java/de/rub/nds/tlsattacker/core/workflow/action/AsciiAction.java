/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.util.IllegalStringAdapter;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.util.Objects;

@XmlRootElement
public abstract class AsciiAction extends TlsAction {

    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String asciiText;

    private final String encoding;

    protected AsciiAction() {
        asciiText = null;
        encoding = null;
    }

    public AsciiAction(String asciiText, String encoding) {
        this.asciiText = asciiText;
        this.encoding = encoding;
    }

    public AsciiAction(String encoding) {
        this.asciiText = null;
        this.encoding = encoding;
    }

    /**
     * @return the asciiText
     */
    public String getAsciiText() {
        return asciiText;
    }

    /**
     * @param asciiText the asciiText to set
     */
    public void setAsciiText(String asciiText) {
        this.asciiText = asciiText;
    }

    public String getEncoding() {
        return encoding;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AsciiAction that = (AsciiAction) o;
        return Objects.equals(asciiText, that.asciiText) && Objects.equals(encoding, that.encoding);
    }

    @Override
    public int hashCode() {
        return Objects.hash(asciiText, encoding);
    }
}
