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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A command object for setting the keys of a target principal.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class SetKeys
{
    private static final Logger log = LoggerFactory.getLogger( SetKeys.class );

    /** The remote Change Password server name. */
    private String hostname;

    /** The remote Change Password server port. */
    private int port;

    /** The Change Password transport. */
    private String transport;


    /**
     * Creates a new instance of ChangePassword.
     *
     * @param hostname
     * @param port 
     * @param transport
     */
    public SetKeys( String hostname, int port, String transport )
    {
        this.hostname = hostname;
        this.port = port;
        this.transport = transport;
    }


    public void execute( KerberosPrincipal targetPrincipal, Map<EncryptionType, EncryptionKey> keys,
        KerberosTicket serviceTicket ) throws PasswordConnectionException
    {
    }
}
