/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EsniKeyRecord;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.EsniKeyRecordParser;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

@XmlRootElement
public class EsniKeyDnsRequestAction extends TlsAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private List<ExtensionMessage> extensions;

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        TlsContext tlsContext;
        tlsContext = state.getTlsContext();
        Config tlsConfig = state.getConfig();

        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }
        String hostname = "_esni." + tlsConfig.getDefaultClientConnection().getHostname();
        Lookup lookup;
        LOGGER.debug("Sending DNS request to get ESNI Resource Record for: " + hostname);
        List<String> esniKeyRecords = new LinkedList();
        try {
            lookup = new Lookup(hostname, Type.TXT);
            lookup.run();
            if (lookup.getResult() == Lookup.SUCCESSFUL) {
                for (Record record : lookup.getAnswers()) {
                    for (String recordString : (List<String>) ((TXTRecord) record).getStrings()) {
                        esniKeyRecords.add(recordString);
                    }
                }
            }
        } catch (TextParseException e) {
            LOGGER.warn("No ESNI DNS Resource Record available for " + hostname);
            setExecuted(true);
            return;
        }
        if (esniKeyRecords.isEmpty()) {
            LOGGER.warn("No ESNI DNS Resource Record available for " + hostname);
            setExecuted(true);
            return;
        }

        String esniKeyRecordStr = esniKeyRecords.get(0);
        byte[] esniKeyRecordBytes;

        try {
            esniKeyRecordBytes = Base64.getMimeDecoder().decode(esniKeyRecordStr);
        } catch (IllegalArgumentException e) {
            LOGGER.warn(
                "Failed to base64 decode Resource Record for" + hostname + ". Resource Record: " + esniKeyRecordStr);
            setExecuted(true);
            return;
        }
        LOGGER.debug("esniKeyRecordStr :" + esniKeyRecordStr);
        LOGGER.debug("esniKeyRecordBytes: " + ArrayConverter.bytesToHexString(esniKeyRecordBytes));

        EsniKeyRecordParser esniKeyParser = new EsniKeyRecordParser(0, esniKeyRecordBytes, tlsContext.getConfig());
        EsniKeyRecord esniKeyRecord = esniKeyParser.parse();
        tlsContext.setEsniRecordBytes(esniKeyRecordBytes);
        tlsContext.setEsniRecordVersion(esniKeyRecord.getVersion());
        tlsContext.setEsniRecordChecksum(esniKeyRecord.getChecksum());
        tlsContext.setEsniServerKeyShareEntries(esniKeyRecord.getKeys());
        tlsContext.setEsniServerCipherSuites(esniKeyRecord.getCipherSuites());
        tlsContext.setEsniPaddedLength(esniKeyRecord.getPaddedLength());
        tlsContext.setEsniKeysNotBefore(esniKeyRecord.getNotBefore());
        tlsContext.setEsniKeysNotAfter(esniKeyRecord.getNotAfter());
        extensions = esniKeyRecord.getExtensions();
        setExecuted(true);
    }

    @Override
    public void reset() {
        setExecuted(false);

    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }
}
