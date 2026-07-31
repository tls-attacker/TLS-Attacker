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
public abstract class TextAction extends TlsAction {

    /** Default encoding for plaintext exchanges (e.g. STARTTLS control channels). */
    public static final String DEFAULT_ENCODING = "US-ASCII";

    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String text;

    private String encoding;

    protected TextAction() {
        text = null;
        encoding = null;
    }

    public TextAction(String text, String encoding) {
        this.text = text;
        this.encoding = encoding;
    }

    public TextAction(String encoding) {
        this.text = null;
        this.encoding = encoding;
    }

    /**
     * @return the text
     */
    public String getText() {
        return text;
    }

    /**
     * @param text the text to set
     */
    public void setText(String text) {
        this.text = text;
    }

    public String getEncoding() {
        return encoding != null ? encoding : DEFAULT_ENCODING;
    }

    public void setEncoding(String encoding) {
        this.encoding = encoding;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TextAction that = (TextAction) o;
        return Objects.equals(text, that.text) && Objects.equals(encoding, that.encoding);
    }

    @Override
    public int hashCode() {
        return Objects.hash(text, encoding);
    }
}
