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
 * Main method class for executing a Kerberos service ticket request.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class Main
{
    private KerberosPrincipal clientPrincipal = new KerberosPrincipal( "hnelson@EXAMPLE.COM" );
    private String password = "cabletr0N";

    private KerberosPrincipal servicePrincipal = new KerberosPrincipal( "ldap/ldap.example.com@EXAMPLE.COM" );

    /** The remote Kerberos server name. */
    private String hostname = "localhost";

    /** The remote Kerberos server port. */
    private int port = 88;


    /**
     * Get a service ticket.
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
        KdcConnection con = new KdcConnection( hostname + ":" + port );
        KerberosTicket tgt = con.getTicketGrantingTicket( clientPrincipal, password );
        con.getServiceTicket( tgt, servicePrincipal );
        con.disconnect();
    }
}
