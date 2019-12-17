/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import java.util.LinkedList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.xbill.DNS.Lookup;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.esni.EsniKeyRecord;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.EsniKeyRecordParser;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.config.Config;
import java.util.Base64;

public class EsniKeyDnsRequestAction extends TlsAction {

    private static final Logger LOGGER = LogManager.getLogger();

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
                for (Record r : lookup.getAnswers()) {
                    for (String s : (List<String>) ((TXTRecord) r).getStrings()) {
                        esniKeyRecords.add(s);
                    }
                }
            }
        } catch (TextParseException e) {
            LOGGER.warn("No ESNI DNS Resource Record available for " + hostname);
            e.printStackTrace();
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
            LOGGER.warn("Can not base64 decode  Resource Record for" + hostname + ". Resource Record: "
                    + esniKeyRecordStr);
            setExecuted(true);
            return;
        }
        LOGGER.debug("esniKeyRecordStr :" + esniKeyRecordStr);
        LOGGER.debug("esniKeyRecordBytes: " + ArrayConverter.bytesToHexString(esniKeyRecordBytes));

        EsniKeyRecordParser esniKeyParser = new EsniKeyRecordParser(0, esniKeyRecordBytes);
        EsniKeyRecord esniKeyRecord = esniKeyParser.parse();

        tlsContext.setEsniRecordBytes(esniKeyRecordBytes);
        tlsContext.setEsniKeysVersion(esniKeyRecord.getVersion());
        tlsContext.setEsniKeysChecksum(esniKeyRecord.getChecksum());
        tlsContext.setEsniServerKeyShareEntryList(esniKeyRecord.getKeyList());
        tlsContext.setEsniServerCiphersuites(esniKeyRecord.getCipherSuiteList());
        tlsContext.setEsniPaddedLength(esniKeyRecord.getPaddedLength());
        tlsContext.setEsniKeysNotBefore(esniKeyRecord.getNotBefore());
        tlsContext.setEsniKeysNotAfter(esniKeyRecord.getNotAfter());
        tlsContext.setEsniExtensions(esniKeyRecord.getExtensionBytes());
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
