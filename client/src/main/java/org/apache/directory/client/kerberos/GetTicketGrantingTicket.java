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


import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.SecureRandom;

import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosPrincipal;

import org.apache.directory.client.kerberos.protocol.KerberosClientUdpCodecFactory;
import org.apache.directory.client.kerberos.protocol.KerberosClientHandler;
import org.apache.directory.server.kerberos.shared.crypto.encryption.CipherTextHandler;
import org.apache.directory.server.kerberos.shared.crypto.encryption.EncryptionType;
import org.apache.directory.server.kerberos.shared.crypto.encryption.KeyUsage;
import org.apache.directory.server.kerberos.shared.exceptions.KerberosException;
import org.apache.directory.server.kerberos.shared.io.encoder.EncryptedDataEncoder;
import org.apache.directory.server.kerberos.shared.messages.KdcRequest;
import org.apache.directory.server.kerberos.shared.messages.MessageType;
import org.apache.directory.server.kerberos.shared.messages.value.EncryptedData;
import org.apache.directory.server.kerberos.shared.messages.value.EncryptedTimeStamp;
import org.apache.directory.server.kerberos.shared.messages.value.EncryptionKey;
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
public class GetTicketGrantingTicket
{
    private static final SecureRandom random = new SecureRandom();
    private static final boolean PA_ENC_TIMESTAMP_REQUIRED = true;

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
        new GetTicketGrantingTicket().go();
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
     * Create a KdcRequest, suitable for requesting a Ticket-Granting Ticket (TGT).
     * 
     * Based on RFC 1510, A.1.  KRB_AS_REQ generation
     */
    private KdcRequest getKdcRequest() throws IOException
    {
        RequestBodyModifier modifier = new RequestBodyModifier();

        KerberosPrincipal principal = new KerberosPrincipal( "hnelson@EXAMPLE.COM" );
        KerberosKey kerberosKey = new KerberosKey( principal, "s3crEt".toCharArray(), "DES" );

        KdcOptions kdcOptions = getKdcOptions();

        int pvno = 5;
        MessageType messageType = MessageType.KRB_AS_REQ;

        PreAuthenticationData[] paData = new PreAuthenticationData[1];

        if ( PA_ENC_TIMESTAMP_REQUIRED )
        {
            CipherTextHandler lockBox = new CipherTextHandler();
            EncryptionKey key = new EncryptionKey( EncryptionType.DES_CBC_MD5, kerberosKey.getEncoded() );

            KerberosTime timeStamp = new KerberosTime();
            EncryptedTimeStamp encryptedTimeStamp = new EncryptedTimeStamp( timeStamp, 0 );

            EncryptedData encryptedData = null;

            try
            {
                encryptedData = lockBox.seal( key, encryptedTimeStamp, KeyUsage.NUMBER1 );
            }
            catch ( KerberosException ke )
            {
                ke.printStackTrace();
            }

            byte[] encodedEncryptedData = EncryptedDataEncoder.encode( encryptedData );

            PreAuthenticationDataModifier preAuth = new PreAuthenticationDataModifier();
            preAuth.setDataType( PreAuthenticationDataType.PA_ENC_TIMESTAMP );
            preAuth.setDataValue( encodedEncryptedData );

            paData[0] = preAuth.getPreAuthenticationData();
        }

        PrincipalName clientName = new PrincipalName( principal.getName(), principal.getNameType() );
        modifier.setClientName( clientName );
        modifier.setRealm( principal.getRealm() );

        PrincipalName serverName = new PrincipalName( "krbtgt/EXAMPLE.COM", principal.getNameType() );
        modifier.setServerName( serverName );

        if ( kdcOptions.get( KdcOptions.POSTDATED ) )
        {
            // body.from := requested starting time;
        }

        KerberosTime endTime = new KerberosTime( System.currentTimeMillis() + ONE_DAY );
        modifier.setTill( endTime );

        if ( kdcOptions.get( KdcOptions.RENEWABLE ) )
        {
            KerberosTime rTime = new KerberosTime( System.currentTimeMillis() + ONE_WEEK );
            modifier.setRtime( rTime );
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

        RequestBody requestBody = modifier.getRequestBody();

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
