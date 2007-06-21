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
package org.apache.directory.client.password;


import java.util.Map;

import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;

import org.apache.directory.server.kerberos.shared.crypto.encryption.EncryptionType;
import org.apache.directory.server.kerberos.shared.messages.value.EncryptionKey;


/**
 * Connection to an RFC 3244 Set/Change Password server.  Connection users may change passwords
 * or set keys for a target principal.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class PasswordConnection
{
    /** The remote Change Password port number. */
    private static final int REMOTE_PORT = 464;

    /** The remote Change Password server name. */
    private String hostname = "localhost";

    /** The remote Change Password server port. */
    private int port = REMOTE_PORT;

    /** The Change Password transport. */
    private String transport = "UDP";


    /**
     * Creates a new instance of PasswordConnection.
     *
     * @param hostname
     */
    public PasswordConnection( String hostname )
    {
        this( hostname, "UDP" );
    }


    /**
     * Creates a new instance of PasswordConnection.
     *
     * @param hostname
     * @param transport
     */
    public PasswordConnection( String hostname, String transport )
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
     * Change a password for a target principal using this password connection.
     *
     * @param targetPrincipal
     * @param newPassword
     * @param serviceTicket
     * @throws PasswordConnectionException
     */
    public void changePassword( KerberosPrincipal targetPrincipal, String newPassword, KerberosTicket serviceTicket )
        throws PasswordConnectionException
    {
        ChangePassword command = new ChangePassword( hostname, port, transport );
        command.execute( targetPrincipal, newPassword, serviceTicket );
    }


    /**
     * Set keys for a target principal using this password connection.
     *
     * @param targetPrincipal
     * @param keys
     * @param serviceTicket
     * @throws PasswordConnectionException
     */
    public void setKeys( KerberosPrincipal targetPrincipal, Map<EncryptionType, EncryptionKey> keys,
        KerberosTicket serviceTicket ) throws PasswordConnectionException
    {
        SetKeys command = new SetKeys( hostname, port, transport );
        command.execute( targetPrincipal, keys, serviceTicket );

        // export keys/set keys
        // write keys to keytab
    }


    /**
     * Disconnects the connection.
     */
    public void disconnect()
    {
        // Wouldn't do anything for UDP.
    }
}
