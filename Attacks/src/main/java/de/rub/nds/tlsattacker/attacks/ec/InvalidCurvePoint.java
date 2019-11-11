/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 */
package de.rub.nds.tlsattacker.attacks.ec;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.math.BigInteger;

/**
 *
 */
public enum InvalidCurvePoint {
  
    SECP160K1(new BigInteger("6F6118AE7199611C0B4F95CFE3B7DEDA68301E69", 16), new BigInteger("F6F9D0E04364C716C25263D7E44CA6C571D22597", 16), new BigInteger("5"), NamedGroup.SECP160K1),
    SECP160R1(new BigInteger("D465C0476AE02C499B0561B9C752C5CFEE8501ED", 16), new BigInteger("5B6394C2C94D9214417E722792D0C07617CC31A6", 16), new BigInteger("5"), NamedGroup.SECP160R1),
    SECP160R2(new BigInteger("2790AABFE83C792584D45D5259ECCA28843D56AA", 16), new BigInteger("5DE5B6B1EC7BDA3940ABA6AD9AE01008040D5949", 16), new BigInteger("5"), NamedGroup.SECP160R2),
    SECP192K1(new BigInteger("7E89D82546F6EDC79CB91F2646E8D7E7AB3FC2F971F1713C", 16), new BigInteger("8A62DA9766C50A90A776C599C421632B46CA9878AB55AF19", 16), new BigInteger("7"), NamedGroup.SECP192K1),
    SECP192R1(new BigInteger("F6DA5E72B35D837EDCDD6E8D211BDBB6565B9708D0447400", 16), new BigInteger("ED15E29256077E3D25C26753FEE705C02FFC0DC8EFDA443A", 16), new BigInteger("5"), NamedGroup.SECP192R1),
    SECP224K1(new BigInteger("54510A6A85EF6144CA057E159DD83C240E3A69B06EE2CAC06BD25AC7", 16), new BigInteger("D2799F20E14C33AB704203F75EBDB38471919531970090DE8D12BC95", 16), new BigInteger("7"), NamedGroup.SECP224K1),
    SECP224R1(new BigInteger("A02F6D2FEBD6C53F11737C43EDDAF9A5026A21245DACA9342CFF7247", 16), new BigInteger("3B0781466C19DCCCAD13A2591A4DFAB7DADF210E9A150CE0C00137D9", 16), new BigInteger("5"), NamedGroup.SECP224R1),
    SECP256K1(new BigInteger("5748979A06D28004D165F01FCA69C80DECAFB0119BA2A7C4C7F84C7AF2DCA311", 16), new BigInteger("D9625DF3DC92015DEB22AC7242ABEBE512B195E973BA657203F1BDEE8662B45A", 16), new BigInteger("7"), NamedGroup.SECP256K1),
    SECP256R1(new BigInteger("21D2EFDDCFDF5C96268A16A8D5B8CB49EAD2DDE206259FE98686188A30CF0339", 16), new BigInteger("D440D09110D30D6CC3CDBBC38284109DB3ACA31F3C6717E29F1CE9D4088D4B1C", 16), new BigInteger("5"), NamedGroup.SECP256R1),
    SECP384R1(new BigInteger("B68083A3FE4F9E46B78D7EDA7DD98FBB712EF7C9899F728D9633A3688B6DE446366668EA1E6CF80996B046719DAD63FF", 16), new BigInteger("FC00B0AFDC553D8A01336C78527231BF2D7C8BAD862225A07761BD0975E968E72204EBF877D9F67A22883512884BA870", 16), new BigInteger("5"), NamedGroup.SECP384R1),
    SECP521R1(new BigInteger("E04ED20B3289E72B4916D3C9095785488D309571BA7E39E0033DB72B471976133EE387F812A0DC2DE796A2C65ACCC220C2E11805FCADAF7F2D29826DF83C0B487F", 16), new BigInteger("7555B523F2A83D26CF76E8BF6F3BD55A6BD7307D617D10F7228ED84920C2832F5AB78472FB1E54E572703E70FB84F4F956F2AA2027F0156DDE1CCE729BA135B02C", 16), new BigInteger("5"), NamedGroup.SECP521R1),
    BRAINPOOLP256R1(new BigInteger("475638180469F3128FCEACFF3D1B2A7052021FABE168456E724C82CE647A0B38", 16), new BigInteger("24392E4B249529608415683ABF8DF8017A577A447B791233BFF1F8D50003C3DA", 16), new BigInteger("5"), NamedGroup.BRAINPOOLP256R1),
    BRAINPOOLP384R1(new BigInteger("7A15487AF637530E2BECC85585C2E36C21447AB4C786F08EF75A1EFBE7785016855AB3B6EFBB9F80517C23C1438A3F18", 16), new BigInteger("1C8AC00FBE2E3CD0994704AC81F8210A283F34D4F351F19525876A14719B8DDAC45315782BB7BBEAB47B0B6061788A9D", 16), new BigInteger("5"), NamedGroup.BRAINPOOLP384R1),
    BRAINPOOLP512R1(new BigInteger("3A52E57C2D5BE39BB3F97C4CF90D81BEE7123CACBC6B7FF6EB03A164CCF0253FDF1AACF7C4AC6B820E6D48145D7854C67DEF4CADAB555D4609E279956450A610", 16), new BigInteger("1C41E102D5E9EF09CA132E808D87D1C0944951572E82C4F9FECACC80714C0C926E5DA09BD775F5C7E2BE54878EE2AC1A091A8653AE9961789202FD2BA21E7999", 16), new BigInteger("5"), NamedGroup.BRAINPOOLP512R1);
    
    private BigInteger publicPointBaseX;
    private BigInteger publicPointBaseY;
    private final NamedGroup namedGroup;
    private BigInteger order;
    
    private InvalidCurvePoint(BigInteger publicPointBaseX, BigInteger publicPointBaseY, BigInteger order, NamedGroup namedGroup)
    {
        this.publicPointBaseX = publicPointBaseX;
        this.publicPointBaseY = publicPointBaseY;
        this.order = order;
        this.namedGroup = namedGroup;
    }
    
    public static InvalidCurvePoint fromNamedGroup(NamedGroup group)
    {
        for(InvalidCurvePoint point : values())
        {
            if(point.getNamedGroup() == group)
            {
                return point;
            }
        }
        return null;
    }
    
    public  NamedGroup getNamedGroup()
    {
        return namedGroup;
    }
    
    public BigInteger getOrder()
    {
        return order;
    }

    /**
     * @return the publicPointBaseX
     */
    public BigInteger getPublicPointBaseX() {
        return publicPointBaseX;
    }

    /**
     * @param publicPointBaseX the publicPointBaseX to set
     */
    public void setPublicPointBaseX(BigInteger publicPointBaseX) {
        this.publicPointBaseX = publicPointBaseX;
    }

    /**
     * @return the publicPointBaseY
     */
    public BigInteger getPublicPointBaseY() {
        return publicPointBaseY;
    }

    /**
     * @param publicPointBaseY the publicPointBaseY to set
     */
    public void setPublicPointBaseY(BigInteger publicPointBaseY) {
        this.publicPointBaseY = publicPointBaseY;
    }

    /**
     * @param order the order to set
     */
    public void setOrder(BigInteger order) {
        this.order = order;
    }
               
}
