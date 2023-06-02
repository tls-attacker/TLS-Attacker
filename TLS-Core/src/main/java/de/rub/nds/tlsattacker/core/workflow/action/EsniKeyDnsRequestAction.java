/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EsniKeyRecord;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.EsniKeyRecordParser;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.UnknownHostException;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;

@XmlRootElement
public class EsniKeyDnsRequestAction extends TlsAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private List<ExtensionMessage> extensions;

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext;
        tlsContext = state.getTlsContext();
        Config tlsConfig = state.getConfig();

        Name domainName;
        Resolver resolver;

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }
        // create DNS resolver and domain name
        String hostname = "_esni." + tlsConfig.getDefaultClientConnection().getHostname();
        try {
            resolver = new SimpleResolver(tlsConfig.getDefaultDnsServer());
            domainName = Name.fromString(hostname + ".");
        } catch (TextParseException e) {
            LOGGER.error("Cannot send DNS query for ip addresses");
            setExecuted(true);
            return;
        } catch (UnknownHostException e) {
            LOGGER.warn("Could not reach Cloudflare DNS server");
            setExecuted(true);
            return;
        }
        // create DNS query
        Record record = Record.newRecord(domainName, Type.TXT, DClass.IN);
        Message message = Message.newQuery(record);
        Message answer;

        LOGGER.debug("Sending DNS request to get ESNI Resource Record for: " + hostname);
        // send Message and read answer
        try {
            answer = resolver.send(message);
        } catch (IOException e) {
            LOGGER.warn("Failed to send DNS query");
            setExecuted(true);
            return;
        }

        List<String> esniKeyRecords = new LinkedList<>();
        // extract encoded esni key(s)
        List<Record> records = answer.getSection(Section.ANSWER);
        for (Record receivedRecord : records) {
            // only parse TXT records
            if (receivedRecord.getType() == Type.TXT) {
                TXTRecord txtRecord = (TXTRecord) receivedRecord;
                esniKeyRecords = txtRecord.getStrings();
            }
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
                    "Failed to base64 decode Resource Record for"
                            + hostname
                            + ". Resource Record: "
                            + esniKeyRecordStr);
            setExecuted(true);
            return;
        }
        LOGGER.debug("esniKeyRecordStr :" + esniKeyRecordStr);
        LOGGER.debug("esniKeyRecordBytes: {}", esniKeyRecordBytes);

        EsniKeyRecordParser esniKeyParser =
                new EsniKeyRecordParser(new ByteArrayInputStream(esniKeyRecordBytes), tlsContext);
        EsniKeyRecord esniKeyRecord = new EsniKeyRecord();
        esniKeyParser.parse(esniKeyRecord);
        tlsContext.setEsniRecordBytes(esniKeyRecordBytes);
        tlsContext.setEsniRecordVersion(esniKeyRecord.getVersion());
        tlsContext.setEsniRecordChecksum(esniKeyRecord.getChecksum());
        tlsContext.setPublicName(esniKeyRecord.getPublicName());
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
