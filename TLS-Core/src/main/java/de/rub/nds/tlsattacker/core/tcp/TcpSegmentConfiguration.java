/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.tcp;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.Serializable;
import java.util.LinkedList;
import java.util.List;

/**
 * Configuration for TCP segmentation. Allows specifying how data should be split across TCP
 * segments.
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class TcpSegmentConfiguration implements Serializable {

    @XmlElement(name = "segment")
    private List<TcpSegment> segments = new LinkedList<>();

    /** Default TCP segment delay in milliseconds between segments */
    @XmlElement(name = "segmentDelay")
    private Integer segmentDelay = 10;

    public TcpSegmentConfiguration() {}

    public TcpSegmentConfiguration(List<TcpSegment> segments) {
        this.segments = segments;
    }

    public List<TcpSegment> getSegments() {
        return segments;
    }

    public void setSegments(List<TcpSegment> segments) {
        this.segments = segments;
    }

    public void addSegment(TcpSegment segment) {
        if (segments == null) {
            segments = new LinkedList<>();
        }
        segments.add(segment);
    }

    public Integer getSegmentDelay() {
        return segmentDelay;
    }

    public void setSegmentDelay(Integer segmentDelay) {
        this.segmentDelay = segmentDelay;
    }

    /** Represents a single TCP segment with offset and length */
    @XmlRootElement
    @XmlAccessorType(XmlAccessType.FIELD)
    public static class TcpSegment implements Serializable {

        @XmlElement(name = "offset")
        private Integer offset;

        @XmlElement(name = "length")
        private Integer length;

        public TcpSegment() {}

        public TcpSegment(Integer offset, Integer length) {
            this.offset = offset;
            this.length = length;
        }

        public Integer getOffset() {
            return offset;
        }

        public void setOffset(Integer offset) {
            this.offset = offset;
        }

        public Integer getLength() {
            return length;
        }

        public void setLength(Integer length) {
            this.length = length;
        }
    }
}
