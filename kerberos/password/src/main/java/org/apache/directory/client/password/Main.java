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


import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;

import org.apache.directory.server.kerberos.shared.messages.components.Ticket;
import org.apache.directory.server.kerberos.shared.messages.value.EncryptionKey;
import org.apache.directory.server.kerberos.shared.store.TicketFactory;


/**
 * Main method class for executing a password change request.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class Main
{
    private static final TicketFactory ticketFactory = new TicketFactory();

    private KerberosPrincipal clientPrincipal = new KerberosPrincipal( "hnelson@EXAMPLE.COM" );
    private KerberosPrincipal serverPrincipal = new KerberosPrincipal( "kadmin/changepw@EXAMPLE.COM" );
    private String newPassword = "cabletr0N";
    private String serverPassword = "s3crEt";

    /** The remote Change Password server name. */
    private String hostname = "localhost";

    /** The remote Change Password server port. */
    private int port = 464;


    /**
     * Change a password.
     * 
     * @param args
     * @throws Exception
     */
    public static void main( String[] args ) throws Exception
    {
        new Main().go();
    }


    private void go() throws Exception
    {
        EncryptionKey serverKey = ticketFactory.getServerKey( serverPrincipal, serverPassword );
        Ticket serviceTicket = ticketFactory.getTicket( clientPrincipal, serverPrincipal, serverKey );
        KerberosTicket convertedTicket = ticketFactory.getKerberosTicket( serviceTicket );

        PasswordConnection con = new PasswordConnection( hostname + ":" + port );
        con.changePassword( clientPrincipal, newPassword, convertedTicket );
        con.disconnect();
    }
}
