/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.directory.client.kerberos;


import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.directory.server.kerberos.shared.crypto.encryption.EncryptionType;


/**
 * Parameters for controlling a connection to a Kerberos server (KDC).
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class KdcControls
{
    /** The number of milliseconds in a minute. */
    public static final int MINUTE = 60000;

    /** The number of milliseconds in a day. */
    public static final int DAY = MINUTE * 1440;

    /** The number of milliseconds in a week. */
    public static final int WEEK = MINUTE * 10080;

    /** The default allowed clockskew */
    private static final long DEFAULT_ALLOWED_CLOCKSKEW = 5 * MINUTE;

    /** The default for requiring encrypted timestamps */
    private static final boolean DEFAULT_USE_PA_ENC_TIMESTAMP = true;

    /** The default for the maximum ticket lifetime */
    private static final int DEFAULT_TGS_MAXIMUM_TICKET_LIFETIME = DAY;

    /** The default for the maximum renewable lifetime */
    private static final int DEFAULT_TGS_MAXIMUM_RENEWABLE_LIFETIME = WEEK;

    /** The default for allowing forwardable tickets */
    private static final boolean DEFAULT_TGS_FORWARDABLE = false;

    /** The default for allowing proxiable tickets */
    private static final boolean DEFAULT_TGS_PROXIABLE = false;

    /** The default for allowing postdatable tickets */
    private static final boolean DEFAULT_TGS_POSTDATED = false;

    /** The default for allowing renewable tickets */
    private static final boolean DEFAULT_TGS_RENEWABLE = true;

    /** The default UDP preference limit */
    private static final int DEFAULT_UDP_PREFERENCE_LIMIT = 1500;

    /** The allowed clock skew. */
    private long allowedClockSkew = DEFAULT_ALLOWED_CLOCKSKEW;

    /** Whether pre-authentication by encrypted timestamp is required. */
    private boolean usePaEncTimestamp = DEFAULT_USE_PA_ENC_TIMESTAMP;

    /** The maximum ticket lifetime. */
    private long maximumTicketLifetime = DEFAULT_TGS_MAXIMUM_TICKET_LIFETIME;

    /** The maximum renewable lifetime. */
    private long maximumRenewableLifetime = DEFAULT_TGS_MAXIMUM_RENEWABLE_LIFETIME;

    /** Whether forwardable addresses are allowed. */
    private boolean isForwardable = DEFAULT_TGS_FORWARDABLE;

    /** Whether proxiable addresses are allowed. */
    private boolean isProxiable = DEFAULT_TGS_PROXIABLE;

    /** Whether postdating is allowed. */
    private boolean isPostdated = DEFAULT_TGS_POSTDATED;

    /** Whether renewable tickets are allowed. */
    private boolean isRenewable = DEFAULT_TGS_RENEWABLE;

    /** The encryption types. */
    private List<EncryptionType> encryptionTypes = new ArrayList<EncryptionType>();

    /** The client addresses. */
    private List<InetAddress> clientAddresses = new ArrayList<InetAddress>();

    /** The UDP preference limit. */
    private int udpPreferenceLimit = DEFAULT_UDP_PREFERENCE_LIMIT;

    private Date startTime;
    private Date endTime;
    private Date renewTime;


    /**
     * Creates a new instance of KdcControls.
     */
    public KdcControls()
    {
        encryptionTypes.add( EncryptionType.DES_CBC_MD5 );
    }


    /**
     * Returns the allowed clock skew.
     *
     * @return The allowed clock skew.
     */
    public long getAllowedClockSkew()
    {
        return allowedClockSkew;
    }


    /**
     * @param allowedClockSkew The allowedClockSkew to set.
     */
    public void setAllowedClockSkew( long allowedClockSkew )
    {
        this.allowedClockSkew = allowedClockSkew;
    }


    /**
     * Returns whether pre-authentication by encrypted timestamp is used.
     *
     * @return Whether pre-authentication by encrypted timestamp is used.
     */
    public boolean isUsePaEncTimestamp()
    {
        return usePaEncTimestamp;
    }


    /**
     * @param usePaEncTimestamp Whether to use a encrypted timestamp pre-authentication.
     */
    public void setUsePaEncTimestamp( boolean usePaEncTimestamp )
    {
        this.usePaEncTimestamp = usePaEncTimestamp;
    }


    /**
     * @return The udpPreferenceLimit.
     */
    public int getUdpPreferenceLimit()
    {
        return udpPreferenceLimit;
    }


    /**
     * Default is UDP.  Set to 1 to use TCP.
     * 
     * @param udpPreferenceLimit 
     */
    public void setUdpPreferenceLimit( int udpPreferenceLimit )
    {
        this.udpPreferenceLimit = udpPreferenceLimit;
    }


    /**
     * Returns the start time.
     *
     * @return The start time.
     */
    public Date getStartTime()
    {
        return startTime;
    }


    /**
     * Sets the start time. If the start time exceeds "now" by more than the
     * clockskew, consider it a POSTDATED request.
     * 
     * @param startTime 
     */
    public void setStartTime( Date startTime )
    {
        this.startTime = startTime;
    }


    /**
     * Returns the end time.
     *
     * @return The end time.
     */
    public Date getEndTime()
    {
        return endTime;
    }


    /**
     * Sets the end time.
     *
     * @param endTime
     */
    public void setEndTime( Date endTime )
    {
        this.endTime = endTime;
    }


    /**
     * Returns the renew time.
     *
     * @return The renew time.
     */
    public Date getRenewTime()
    {
        return renewTime;
    }


    /**
     * Sets the renew time.
     *
     * @param renewTime
     */
    public void setRenewTime( Date renewTime )
    {
        this.renewTime = renewTime;
    }


    /**
     * Returns whether to request a forwardable ticket.
     *
     * @return true if the request is for a forwardable ticket.
     */
    public boolean isForwardable()
    {
        return isForwardable;
    }


    /**
     * Sets whether to request a forwardable ticket.
     *
     * @param isForwardable
     */
    public void setForwardable( boolean isForwardable )
    {
        this.isForwardable = isForwardable;
    }


    /**
     * Returns whether to request a postdated ticket.
     * 
     * @return true if the request is for a postdated ticket.
     */
    public boolean isPostdated()
    {
        return isPostdated;
    }


    /**
     * Sets whether to request a postdated ticket.
     * 
     * @param isPostdated
     */
    public void setPostdated( boolean isPostdated )
    {
        this.isPostdated = isPostdated;
    }


    /**
     * Returns whether to request a proxiable ticket.
     * 
     * @return true if the request is for a proxiable ticket.
     */
    public boolean isProxiable()
    {
        return isProxiable;
    }


    /**
     * Sets whether to request a proxiable ticket.
     *
     * @param isProxiable
     */
    public void setProxiable( boolean isProxiable )
    {
        this.isProxiable = isProxiable;
    }


    /**
     * Returns whether to request a renewable ticket.
     * 
     * @return true if the request is for a renewable ticket.
     */
    public boolean isRenewable()
    {
        return isRenewable;
    }


    /**
     * Sets whether to request a renewable ticket.
     * 
     * @param isRenewable
     */
    public void setRenewable( boolean isRenewable )
    {
        this.isRenewable = isRenewable;
    }


    /**
     * @return The maximumTicketLifetime.
     */
    public long getMaximumTicketLifetime()
    {
        return maximumTicketLifetime;
    }


    /**
     * @param maximumTicketLifetime The maximumTicketLifetime to set.
     */
    public void setMaximumTicketLifetime( long maximumTicketLifetime )
    {
        this.maximumTicketLifetime = maximumTicketLifetime;
    }


    /**
     * @return The maximumRenewableLifetime.
     */
    public long getMaximumRenewableLifetime()
    {
        return maximumRenewableLifetime;
    }


    /**
     * @param maximumRenewableLifetime The maximumRenewableLifetime to set.
     */
    public void setMaximumRenewableLifetime( long maximumRenewableLifetime )
    {
        this.maximumRenewableLifetime = maximumRenewableLifetime;
    }


    /**
     * Returns the encryption types.
     *
     * @return The encryption types.
     */
    public List<EncryptionType> getEncryptionTypes()
    {
        return encryptionTypes;
    }


    /**
     * @param encryptionTypes The encryption types to set.
     */
    public void setEncryptionTypes( List<EncryptionType> encryptionTypes )
    {
        this.encryptionTypes = encryptionTypes;
    }


    /**
     * Returns the client addresses.
     *
     * @return The client addresses.
     */
    public List<InetAddress> getClientAddresses()
    {
        return clientAddresses;
    }


    /**
     * Sets the client addresses.
     *
     * @param clientAddresses
     */
    public void setClientAddresses( List<InetAddress> clientAddresses )
    {
        this.clientAddresses = clientAddresses;
    }
}
