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


import java.net.InetSocketAddress;
import java.security.SecureRandom;

import javax.security.auth.kerberos.KerberosPrincipal;

import org.apache.directory.client.kerberos.protocol.KerberosClientUdpCodecFactory;
import org.apache.directory.client.kerberos.protocol.KerberosClientHandler;
import org.apache.directory.server.kerberos.shared.crypto.encryption.EncryptionType;
import org.apache.directory.server.kerberos.shared.messages.KdcRequest;
import org.apache.directory.server.kerberos.shared.messages.MessageType;
import org.apache.directory.server.kerberos.shared.messages.value.KdcOptions;
import org.apache.directory.server.kerberos.shared.messages.value.KerberosTime;
import org.apache.directory.server.kerberos.shared.messages.value.PreAuthenticationData;
import org.apache.directory.server.kerberos.shared.messages.value.PreAuthenticationDataModifier;
import org.apache.directory.server.kerberos.shared.messages.value.PreAuthenticationDataType;
import org.apache.directory.server.kerberos.shared.messages.value.PrincipalName;
import org.apache.directory.server.kerberos.shared.messages.value.RequestBody;
import org.apache.directory.server.kerberos.shared.messages.value.RequestBodyModifier;
import org.apache.mina.common.ConnectFuture;
import org.apache.mina.common.IoConnector;
import org.apache.mina.common.IoSession;
import org.apache.mina.filter.LoggingFilter;
import org.apache.mina.filter.codec.ProtocolCodecFilter;
import org.apache.mina.transport.socket.nio.DatagramConnector;


/**
 * A command-line client for requesting Kerberos tickets.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class GetServiceTicket
{
    private static final SecureRandom random = new SecureRandom();

    /** The remote Kerberos server name. */
    private String hostname = "localhost";

    /** The remote Kerberos port number. */
    private static final int REMOTE_PORT = 88;

    /** One day in milliseconds, used for default end time. */
    private static final int ONE_DAY = 86400000;

    /** One week in milliseconds, used for default renewal period. */
    private static final int ONE_WEEK = 86400000 * 7;


    /**
     * Get a Ticket-Granting Ticket.
     * 
     * @param args
     * @throws Exception
     */
    public static void main( String[] args ) throws Exception
    {
        new GetServiceTicket().go();
    }


    /**
     * Make the request for a Ticket-Granting Ticket.
     */
    public void go()
    {
        IoConnector connector = new DatagramConnector();

        connector.getFilterChain()
            .addLast( "codec", new ProtocolCodecFilter( KerberosClientUdpCodecFactory.getInstance() ) );
        connector.getFilterChain().addLast( "logger", new LoggingFilter() );

        ConnectFuture future = connector.connect( new InetSocketAddress( hostname, REMOTE_PORT ),
            new KerberosClientHandler() );

        future.join();

        IoSession session = future.getSession();

        try
        {
            KdcRequest request = getKdcRequest();
            session.write( request );
        }
        catch ( Exception e )
        {
            e.printStackTrace();
        }

        session.getCloseFuture().join();
    }


    /**
     * Create a KdcRequest, suitable for requesting a service Ticket.
     * 
     * Based on RFC 1510, A.5.  KRB_TGS_REQ generation
     */
    private KdcRequest getKdcRequest()
    {
        RequestBodyModifier modifier = new RequestBodyModifier();

        KerberosPrincipal principal = new KerberosPrincipal( "hnelson@EXAMPLE.COM" );

        int pvno = 5;
        MessageType messageType = MessageType.KRB_TGS_REQ;

        KdcOptions kdcOptions = getKdcOptions();

        /*
         If the TGT is not for the realm of the end-server
         then the sname will be for a TGT for the end-realm
         and the realm of the requested ticket (body.realm)
         will be that of the TGS to which the TGT we are
         sending applies.
         */
        PrincipalName serverName = new PrincipalName( "ldap/ldap.example.com", principal.getNameType() );
        modifier.setServerName( serverName );
        modifier.setRealm( principal.getRealm() );

        // Set the requested starting time.
        if ( kdcOptions.get( KdcOptions.POSTDATED ) )
        {
            KerberosTime fromTime = new KerberosTime();
            modifier.setFrom( fromTime );
        }

        KerberosTime endTime = new KerberosTime( System.currentTimeMillis() + ONE_DAY );
        modifier.setTill( endTime );

        if ( kdcOptions.get( KdcOptions.RENEWABLE ) )
        {
            KerberosTime renewableTime = new KerberosTime( System.currentTimeMillis() + ONE_WEEK );
            modifier.setRtime( renewableTime );
        }

        modifier.setKdcOptions( kdcOptions );

        modifier.setNonce( getNonce() );

        EncryptionType[] encryptionTypes = new EncryptionType[1];
        encryptionTypes[0] = EncryptionType.DES_CBC_MD5;

        modifier.setEType( encryptionTypes );

        /*
         if ( user supplied addresses )
         {
         body.addresses := user's addresses;
         }
         */

        /*
         omit body.enc-authorization-data;
         */

        if ( kdcOptions.get( KdcOptions.ENC_TKT_IN_SKEY ) )
        {
            // modifier.setAdditionalTickets( secondTGT )
        }

        RequestBody requestBody = modifier.getRequestBody();

        // TODO - check := generate_checksum (req.body,checksumtype);

        PreAuthenticationData[] paData = new PreAuthenticationData[1];

        PreAuthenticationDataModifier preAuth = new PreAuthenticationDataModifier();
        preAuth.setDataType( PreAuthenticationDataType.PA_TGS_REQ );

        // TODO - padata[0].padata-value := create a KRB_AP_REQ using the TGT and checksum
        preAuth.setDataValue( new byte[]
            { ( byte ) 0x00 } );

        paData[0] = preAuth.getPreAuthenticationData();

        return new KdcRequest( pvno, messageType, paData, requestBody );
    }


    private int getNonce()
    {
        return random.nextInt();
    }


    private KdcOptions getKdcOptions()
    {
        /*
         Forwardable Ticket false
         Forwarded Ticket false
         Proxiable Ticket false
         Proxy Ticket false
         Postdated Ticket false
         Renewable Ticket false
         Initial Ticket false
         */
        return new KdcOptions();
    }
}
