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
import java.io.IOException;
import java.nio.charset.Charset;

/**
 * A simple action to print the last handled application data to console. Per
 * default, this prints the raw byte values of the application data as a hex
 * string. An charset for simple encoding can be given to get readable output
 * (if possible).
 *
 * TODO: Don't know if it's useful to have the data in worfklow trace output.
 *
 * TODO: If bored, build a similar action that can decode chunked + gziped HTTP
 * data :-)
 * 
 * @author Lucas Hartmann <lucas.hartmann@rub.de>
 */
public class PrintLastHandledApplicationDataAction extends TLSAction {

    private String lastHandledApplicationData = null;

    /**
     * If set, the lastHandledApplicationData will be encoded as String using
     * the given charset (that is StandardCharsets.UTF_8,
     * StandardCharsets.ISO_8859_1,...) before printing. If unset, plot raw
     * bytes as hex string.
     */
    private Charset stringEncoding = null;

    @Override
    public void execute(State state) throws WorkflowExecutionException, IOException {
        byte[] rawBytes = state.getTlsContext(contextAlias).getChooser().getLastHandledApplicationMessageData();
        if (stringEncoding != null) {
            lastHandledApplicationData = new String(rawBytes, stringEncoding);
        } else {
            lastHandledApplicationData = ArrayConverter.bytesToHexString(rawBytes);
        }
        System.out.println(lastHandledApplicationData);
    }

    public String getLastHandledApplicationData() {
        return lastHandledApplicationData;
    }

    public void setLastHandledApplicationData(String lastHandledApplicationData) {
        this.lastHandledApplicationData = lastHandledApplicationData;
    }

    public Charset getStringEncoding() {
        return stringEncoding;
    }

    public void setStringEncoding(Charset stringEncoding) {
        this.stringEncoding = stringEncoding;
    }

    @Override
    public boolean executedAsPlanned() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void reset() {
        lastHandledApplicationData = null;
    }

}
