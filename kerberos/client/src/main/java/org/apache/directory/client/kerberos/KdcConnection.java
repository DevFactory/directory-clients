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


import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;


/**
 * Connection to an RFC 4120 Kerberos server (KDC).  Connection users may request Ticket-Granting
 * Tickets (TGT) or service tickets based on TGTs.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class KdcConnection
{
    /** The remote Kerberos port number. */
    private static final int REMOTE_PORT = 88;

    /** The remote Kerberos server name. */
    private String hostname = "localhost";

    /** The remote Kerberos server port. */
    private int port = REMOTE_PORT;

    /** The Kerberos transport. */
    private String transport = "UDP";


    /**
     * Creates a new instance of KdcConnection.
     *
     * @param hostname
     */
    public KdcConnection( String hostname )
    {
        this( hostname, "UDP" );
    }


    /**
     * Creates a new instance of KdcConnection.
     *
     * @param hostname
     * @param transport
     */
    public KdcConnection( String hostname, String transport )
    {
        if ( hostname.contains( ":" ) )
        {
            String[] split = hostname.split( ":" );
            this.hostname = split[0];
            this.port = Integer.valueOf( split[1] );
        }
        else
        {
            this.hostname = hostname;
        }

        if ( !( transport.toLowerCase().equals( "tcp" ) || transport.toLowerCase().equals( "udp" ) ) )
        {
            throw new IllegalArgumentException( "Transport must be UDP or TCP." );
        }
        else
        {
            this.transport = transport;
        }
    }


    /**
     * Get a Ticket-Granting Ticket (TGT).
     *
     * @param clientPrincipal
     * @param password
     * @return The Ticket-Granting Ticket (TGT).
     * @throws KdcConnectionException
     */
    public KerberosTicket getTicketGrantingTicket( KerberosPrincipal clientPrincipal, String password )
        throws KdcConnectionException
    {
        return getTicketGrantingTicket( clientPrincipal, password, new KdcControls() );
    }


    /**
     * Get a Ticket-Granting Ticket (TGT).
     *
     * @param clientPrincipal
     * @param password
     * @param controls
     * @return The Ticket-Granting Ticket (TGT).
     * @throws KdcConnectionException
     */
    public KerberosTicket getTicketGrantingTicket( KerberosPrincipal clientPrincipal, String password,
        KdcControls controls ) throws KdcConnectionException
    {
        GetTicketGrantingTicket command = new GetTicketGrantingTicket( hostname, port, transport );
        return command.execute( clientPrincipal, password, controls );
    }


    /**
     * Get a service ticket.
     * 
     * @param tgt 
     * @param servicePrincipal 
     * @return The service ticket.
     * @throws KdcConnectionException
     */
    public KerberosTicket getServiceTicket( KerberosTicket tgt, KerberosPrincipal servicePrincipal )
        throws KdcConnectionException
    {
        return getServiceTicket( tgt, servicePrincipal, new KdcControls() );
    }


    /**
     * Get a service ticket.
     * 
     * @param tgt 
     * @param servicePrincipal 
     * @param controls 
     * @return The service ticket.
     * @throws KdcConnectionException
     */
    public KerberosTicket getServiceTicket( KerberosTicket tgt, KerberosPrincipal servicePrincipal, KdcControls controls )
        throws KdcConnectionException
    {
        GetServiceTicket command = new GetServiceTicket( hostname, port, transport );
        return command.execute( tgt, servicePrincipal, controls );
    }


    /**
     * Disconnects the connection.
     */
    public void disconnect()
    {
        // Wouldn't do anything for UDP.
    }
}
