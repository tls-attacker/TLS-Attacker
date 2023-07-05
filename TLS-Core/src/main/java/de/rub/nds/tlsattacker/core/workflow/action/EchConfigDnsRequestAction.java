/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.SvcbType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EchConfig;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.EchConfigParser;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.UnknownHostException;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;

@XmlRootElement
public class EchConfigDnsRequestAction extends TlsAction {
    private static final Logger LOGGER = LogManager.getLogger();

    private List<ExtensionMessage> extensions;

    private TlsContext tlsContext;
    private Config tlsConfig;

    @Override
    public void execute(State state) throws WorkflowExecutionException {

        tlsContext = state.getTlsContext();
        tlsConfig = state.getConfig();

        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        // extract firstHostName
        String hostname = tlsConfig.getDefaultClientConnection().getHostname();
        Name domainName;
        try {
            domainName = Name.fromString(hostname + ".");
        } catch (TextParseException e) {
            LOGGER.error(
                    "Cannot send DNS query for ip addresses. Please provide the domain name in the server_name parameter");
            setExecuted(true);
            return;
        }

        // get HTTPS answer from DNS
        Message answer;
        try {
            answer = getHttpRecordAnswer(domainName);
        } catch (UnknownHostException e) {
            LOGGER.warn("Could not reach DNS server");
            setExecuted(true);
            return;
        } catch (IOException e) {
            LOGGER.warn("Failed to send DNS query");
            setExecuted(true);
            return;
        }

        // get ECH configs for specified hostname
        List<EchConfig> echConfigs = new LinkedList<>();
        echConfigs.addAll(getEchConfigsForAnswer(domainName, answer));

        if (!echConfigs.isEmpty()) {
            LOGGER.info("ECH config found for " + domainName);
            tlsContext.setEchConfig(echConfigs.get(0));
            setExecuted(true);
            return;
        }

        // if we did not receive configs for the specified hostname try the referred authority
        LOGGER.warn("No ECH Configs available for " + hostname + ". Trying authority server.");
        domainName = getAuthorityForAnswer(answer);
        if (domainName == null) {
            LOGGER.warn("No authority server given for " + hostname);
            setExecuted(true);
            return;
        }

        // query answer for referred authority

        // get HTTPS answer from DNS
        try {
            answer = getHttpRecordAnswer(domainName);
        } catch (UnknownHostException e) {
            LOGGER.warn("Could not reach DNS server");
            setExecuted(true);
            return;
        } catch (IOException e) {
            LOGGER.warn("Failed to send DNS query");
            setExecuted(true);
            return;
        }

        echConfigs.addAll(getEchConfigsForAnswer(domainName, answer));

        if (!echConfigs.isEmpty()) {
            LOGGER.info("ECH config found for " + domainName);
            tlsContext.setEchConfig(echConfigs.get(0));
        } else {
            // still no ECH entry on referred server
            LOGGER.warn("No ECH Configs available for " + hostname);
        }
        setExecuted(true);
    }

    /**
     * Extracts a possible authority server from the given Dns entry.
     *
     * @param answer The Dns entry
     * @return Domain name of the authority server. Null, if not found
     */
    private Name getAuthorityForAnswer(Message answer) {
        Name referredHost = null;

        List<Record> records = answer.getSection(Section.AUTHORITY);
        for (Record receivedRecord : records) {
            // only parse HTTPS records
            if (receivedRecord.getType() == Type.SOA) {
                SOARecord soaRecord = (SOARecord) receivedRecord;
                referredHost = soaRecord.getName();
            }
        }
        return referredHost;
    }

    /**
     * Returns a list of EchConfigs based on the given Dns entry.
     *
     * @param domainName Hostname of the server
     * @param answer Dns entry
     */
    private List<EchConfig> getEchConfigsForAnswer(Name domainName, Message answer) {

        List<EchConfig> echConfigs = new LinkedList<>();

        List<String> echConfigStrings = new LinkedList<>();
        // extract encoded ech config(s)
        List<Record> records = answer.getSection(Section.ANSWER);
        for (Record receivedRecord : records) {
            // only parse HTTPS records
            if (receivedRecord.getType() == Type.HTTPS) {
                HTTPSRecord httpsRecord = (HTTPSRecord) receivedRecord;
                for (Integer i : httpsRecord.getSvcParamKeys()) {
                    // only parse the ech part
                    if (Objects.equals(i, SvcbType.ECH.getCode())) {
                        // if its present we know the server offers an ECH key
                        echConfigStrings.add(httpsRecord.getSvcParamValue(i).toString());
                    }
                }
            }
        }

        if (echConfigStrings.isEmpty()) {
            return echConfigs;
        }

        // we expect only one string that can hold multiple configs instead of multiple strings
        // (different to ENSI)
        String echConfigsStr = echConfigStrings.get(0);
        byte[] echConfigBytes;

        try {
            echConfigBytes = Base64.getMimeDecoder().decode(echConfigsStr);
        } catch (IllegalArgumentException e) {
            LOGGER.warn(
                    "Failed to base64 decode Resource Record for"
                            + domainName
                            + ". ECH Config: "
                            + echConfigsStr);
            return echConfigs;
        }
        LOGGER.debug("echConfigStr :" + echConfigsStr);
        LOGGER.debug("echConfigBytes: " + ArrayConverter.bytesToHexString(echConfigBytes));

        EchConfigParser echConfigParser =
                new EchConfigParser(new ByteArrayInputStream(echConfigBytes), tlsContext);
        echConfigParser.parse(echConfigs);
        return echConfigs;
    }

    /**
     * Returns a Dns answer for the given domain name.
     *
     * @param domainName The server's domain name
     */
    private Message getHttpRecordAnswer(Name domainName) throws IOException {
        Resolver resolver;

        resolver = new SimpleResolver(tlsConfig.getDefaultDnsServer());

        // create DNS query
        Record record = Record.newRecord(domainName, Type.HTTPS, DClass.IN);
        Message message = Message.newQuery(record);
        Message answer;

        LOGGER.debug("Sending DNS request to get ECH Config for: " + domainName);
        // send Message and read answer
        answer = resolver.send(message);
        return answer;
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
