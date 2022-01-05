/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.certificate.transparency.logs;

import de.rub.nds.tlsattacker.core.certificate.transparency.SignedCertificateTimestampSignature;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class ChromeCtLogListParser implements CtLogListParser {

    protected static final Logger LOGGER = LogManager.getLogger();

    private JSONParser jsonParser = new JSONParser();

    @Override
    public CtLogList parseLogList(String filename) {

        CtLogList ctLogList = new CtLogList();

        InputStream inputStream = ChromeCtLogListParser.class.getClassLoader().getResourceAsStream(filename);
        InputStreamReader streamReader = new InputStreamReader(inputStream, StandardCharsets.UTF_8);
        BufferedReader bufferedReader = new BufferedReader(streamReader);

        try {
            JSONObject jsonFile = (JSONObject) jsonParser.parse(bufferedReader);
            JSONArray operators = (JSONArray) jsonFile.get("operators");

            for (Object operatorObj : operators) {
                JSONObject operator = (JSONObject) operatorObj;
                String operatorName = (String) operator.get("name");
                JSONArray logs = (JSONArray) operator.get("logs");

                for (Object logObj : logs) {
                    JSONObject log = (JSONObject) logObj;

                    String description = (String) log.get("description");
                    byte[] logId = Base64.getDecoder().decode((String) log.get("log_id"));
                    byte[] publicKey = Base64.getDecoder().decode((String) log.get("key"));

                    CtLog ctLog = new CtLog(description, operatorName, logId, publicKey);
                    ctLogList.addCtLog(ctLog);
                }
            }
        } catch (Exception e) {
            LOGGER.warn("Could not parse Chrome CT log list from " + filename, e);
        }
        return ctLogList;
    }
}
