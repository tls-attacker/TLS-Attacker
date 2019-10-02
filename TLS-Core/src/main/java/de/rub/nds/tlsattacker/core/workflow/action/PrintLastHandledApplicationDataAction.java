/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import java.nio.charset.Charset;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A simple action to print the last handled application data to console. Per
 * default, this prints the raw byte values of the application data as a hex
 * string. An charset for simple encoding can be given to get readable output
 */
public class PrintLastHandledApplicationDataAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private String lastHandledApplicationData = null;

    /**
     * If set, the lastHandledApplicationData will be encoded as String using
     * the given charset (that is UTF-8, ISO-8859-1,...) before printing. If
     * unset, plot raw bytes as hex string.
     *
     * Note: we are using String instead of Charset for serialization
     * purposes...
     *
     * <a href=
     * "https://docs.oracle.com/javase/7/docs/api/java/nio/charset/Charset.html"
     * >Charset.html</a> for a list of supported charset names
     */
    private String stringEncoding = null;

    public PrintLastHandledApplicationDataAction() {
    }

    public PrintLastHandledApplicationDataAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        byte[] rawBytes = state.getTlsContext(getConnectionAlias()).getChooser().getLastHandledApplicationMessageData();
        if (stringEncoding != null) {
            lastHandledApplicationData = new String(rawBytes, Charset.forName(stringEncoding));
        } else {
            lastHandledApplicationData = ArrayConverter.bytesToHexString(rawBytes);
        }
        CONSOLE.info("Last handled application data: " + lastHandledApplicationData);
        setExecuted(true);
    }

    public String getLastHandledApplicationData() {
        return lastHandledApplicationData;
    }

    public void setLastHandledApplicationData(String lastHandledApplicationData) {
        this.lastHandledApplicationData = lastHandledApplicationData;
    }

    public String getStringEncoding() {
        return stringEncoding;
    }

    /**
     * Set encoding. Supplied String must match an element from Charset.
     * Example: US-ASCII Available charsets can be found in StandardCharsets
     *
     * @param stringEncoding
     *            The enconding that should be used
     *
     */
    public void setStringEncoding(String stringEncoding) {
        this.stringEncoding = stringEncoding;
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    @Override
    public void reset() {
        setExecuted(false);
        lastHandledApplicationData = null;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 53 * hash + Objects.hashCode(this.lastHandledApplicationData);
        hash = 53 * hash + Objects.hashCode(this.stringEncoding);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final PrintLastHandledApplicationDataAction other = (PrintLastHandledApplicationDataAction) obj;
        if (!Objects.equals(this.lastHandledApplicationData, other.lastHandledApplicationData)) {
            return false;
        }
        return Objects.equals(this.stringEncoding, other.stringEncoding);
    }
}
