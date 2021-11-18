/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.state;

public class Session {

    private byte[] sessionId;
    private byte[] masterSecret;
    private byte[] sessionTicket;
    private Integer internalTicketId;
    private static final Integer NO_TICKET = -1;
    private static final Integer AUTO_SET_ID = -2;

    public Session(byte[] sessionId, byte[] masterSecret) {
        this.sessionId = sessionId;
        this.masterSecret = masterSecret;
        this.internalTicketId = NO_TICKET;
        this.sessionTicket = new byte[0];
    }

    public Session(byte[] sessionId, byte[] masterSecret, byte[] sessionTicket) {
        this.sessionId = sessionId;
        this.masterSecret = masterSecret;
        this.internalTicketId = AUTO_SET_ID;
        this.sessionTicket = sessionTicket;
    }

    public byte[] getSessionId() {
        return sessionId;
    }

    public void setSessionId(byte[] sessionId) {
        this.sessionId = sessionId;
    }

    public byte[] getMasterSecret() {
        return masterSecret;
    }

    public void setMasterSecret(byte[] masterSecret) {
        this.masterSecret = masterSecret;
    }

    public byte[] getSessionTicket() {
        return sessionTicket;
    }

    public void setSessionTicket(byte[] sessionTicket, Integer internalTicketId) {
        this.internalTicketId = internalTicketId;
        this.sessionTicket = sessionTicket;
    }

    public int getInternalTicketId() {
        return internalTicketId;
    }

    public void setInternalTicketId(Integer internalTicketId) {
        this.internalTicketId = internalTicketId;
    }

    public Boolean hasTicket() {
        return this.internalTicketId != -1;
    }
}
