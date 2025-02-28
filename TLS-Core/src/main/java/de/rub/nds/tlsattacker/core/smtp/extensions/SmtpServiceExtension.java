/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.extensions;

import jakarta.xml.bind.annotation.XmlSeeAlso;

/** Enum of SMTP service extensions as maintained by IANA. */
@XmlSeeAlso({
        _8BITMIMEExtension.class,
        ATRNExtension.class,
        AUTHExtension.class,
        BINARYMIMEExtension.class,
        BURLExtension.class,
        CHECKPOINTExtension.class,
        CHUNKINGExtension.class,
        CONNEGExtension.class,
        CONPERMExtension.class,
        DELIVERBYExtension.class,
        DSNExtension.class,
        ENHANCEDSTATUSCODESExtension.class,
        ETRNExtension.class,
        EXPNExtension.class,
        FUTURERELEASEExtension.class,
        HELPExtension.class,
        LIMITSExtension.class,
        LocalSmtpServiceExtension.class,
        MT_PRIORITYExtension.class,
        MTRKExtension.class,
        NO_SOLICITINGExtension.class,
        ONEXExtension.class,
        PIPELININGExtension.class,
        REQUIRETLSExtension.class,
        RRVSExtension.class,
        SAMLExtension.class,
        SENDExtension.class,
        SIZEExtension.class,
        SMTPUTF8Extension.class,
        SOMLExtension.class,
        STARTTLSExtension.class,
        SUBMITTERExtension.class,
        TURNExtension.class,
        UnknownEHLOExtension.class,
        UTF8SMTPExtension.class,
        VERBExtension.class
})
public abstract class SmtpServiceExtension {

    private final String ehloKeyword;
    private String parameters = null;

    public SmtpServiceExtension(String ehloKeyword, String parameters) {
        this.ehloKeyword = ehloKeyword;
        this.parameters = parameters;
    }

    public SmtpServiceExtension(String ehloKeyword) {
        this.ehloKeyword = ehloKeyword;
    }

    public String getEhloKeyword() {
        return ehloKeyword;
    }

    public boolean isImplemented() {
        return false;
    }

    public String getParameters() {
        return parameters;
    }

    public String serialize() {
        StringBuilder sb = new StringBuilder();

        sb.append(this.ehloKeyword);
        if (this.parameters != null) {
            sb.append(' ');
            sb.append(parameters);
        }

        return sb.toString();
    }
}
