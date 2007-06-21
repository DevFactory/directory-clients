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
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.Date;

import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;

import org.apache.directory.client.kerberos.protocol.KerberosClientHandler;
import org.apache.directory.server.kerberos.shared.crypto.encryption.CipherTextHandler;
import org.apache.directory.server.kerberos.shared.crypto.encryption.EncryptionType;
import org.apache.directory.server.kerberos.shared.crypto.encryption.KeyUsage;
import org.apache.directory.server.kerberos.shared.exceptions.KerberosException;
import org.apache.directory.server.kerberos.shared.io.encoder.EncryptedDataEncoder;
import org.apache.directory.server.kerberos.shared.io.encoder.TicketEncoder;
import org.apache.directory.server.kerberos.shared.messages.ErrorMessage;
import org.apache.directory.server.kerberos.shared.messages.KdcReply;
import org.apache.directory.server.kerberos.shared.messages.KdcRequest;
import org.apache.directory.server.kerberos.shared.messages.MessageType;
import org.apache.directory.server.kerberos.shared.messages.components.EncKdcRepPart;
import org.apache.directory.server.kerberos.shared.messages.components.Ticket;
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
import org.apache.mina.transport.socket.nio.DatagramConnector;
import org.apache.mina.transport.socket.nio.SocketConnector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A command object for requesting a Kerberos Ticket-Granting Ticket (TGT).
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class GetTicketGrantingTicket
{
    private static final Logger log = LoggerFactory.getLogger( GetTicketGrantingTicket.class );

    private static final SecureRandom random = new SecureRandom();

    private static final CipherTextHandler cipherTextHandler = new CipherTextHandler();

    /** The remote Kerberos server name. */
    private String hostname;

    /** The remote Kerberos server port. */
    private int port;

    /** The Kerberos transport. */
    private String transport;

    /** The client's encryption key. */
    private EncryptionKey clientKey;


    /**
     * Creates a new instance of GetTicketGrantingTicket.
     *
     * @param hostname
     * @param port 
     * @param transport
     */
    public GetTicketGrantingTicket( String hostname, int port, String transport )
    {
        this.hostname = hostname;
        this.port = port;
        this.transport = transport;
    }


    /**
     * Execute the request for a Ticket-Granting Ticket (TGT).
     * 
     * @param clientPrincipal 
     * @param password 
     * @param controls 
     * @return The TGT.
     * @throws KdcConnectionException 
     */
    public KerberosTicket execute( KerberosPrincipal clientPrincipal, String password, KdcControls controls )
        throws KdcConnectionException
    {
        IoConnector connector = getConnector( transport );

        ConnectFuture future = connector.connect( new InetSocketAddress( hostname, port ), new KerberosClientHandler() );

        future.join();

        IoSession session = future.getSession();

        try
        {
            KdcRequest request = getKdcRequest( clientPrincipal, password, controls );
            session.write( request );
        }
        catch ( Exception e )
        {
            log.debug( "Unexpected exception.", e );
        }

        session.getCloseFuture().join();

        Object message = session.getAttribute( "reply" );

        if ( message instanceof KdcReply )
        {
            KdcReply reply = ( KdcReply ) message;
            return processKdcReply( reply );
        }
        else
        {
            if ( message instanceof ErrorMessage )
            {
                ErrorMessage error = ( ErrorMessage ) message;
                processError( error );
            }
        }

        log.error( "KDC returned error; ticket will be null." );
        return null;
    }


    private void processError( ErrorMessage error ) throws KdcConnectionException
    {
        int errorCode = error.getErrorCode();
        String errorText = error.getExplanatoryText();

        throw new KdcConnectionException( errorText + " (" + errorCode + ")" );
    }


    private KerberosTicket processKdcReply( KdcReply reply ) throws KdcConnectionException
    {
        Ticket ticket = reply.getTicket();

        log.debug( "Received ticket for '{}' to access '{}'.", reply.getClientPrincipal().getName(), ticket
            .getServerPrincipal().getName() );

        byte[] ticketBytes = null;
        try
        {
            ticketBytes = TicketEncoder.encodeTicket( ticket );
        }
        catch ( IOException ioe )
        {
            throw new KdcConnectionException( "Error converting ticket.", ioe );
        }

        KerberosPrincipal client = reply.getClientPrincipal();
        KerberosPrincipal server = ticket.getServerPrincipal();

        EncryptedData encRepPart = reply.getEncPart();

        EncKdcRepPart repPart;

        try
        {
            repPart = ( EncKdcRepPart ) cipherTextHandler.unseal( EncKdcRepPart.class, clientKey, encRepPart,
                KeyUsage.NUMBER3 );
        }
        catch ( KerberosException ke )
        {
            log.debug( "Unexpected exception.", ke );
            return null;
        }

        byte[] sessionKey = repPart.getKey().getKeyValue();
        int keyType = repPart.getKey().getKeyType().getOrdinal();
        Date endTime = repPart.getEndTime().toDate();

        // might be null
        boolean[] flags = null;
        Date authTime = null;
        Date startTime = null;
        Date renewTill = null;
        InetAddress[] clientAddresses = null;

        return new KerberosTicket( ticketBytes, client, server, sessionKey, keyType, flags, authTime, startTime,
            endTime, renewTill, clientAddresses );
    }


    /**
     * Create a KdcRequest, suitable for requesting a Ticket-Granting Ticket (TGT).
     * 
     * Based on RFC 1510, A.1.  KRB_AS_REQ generation
     */
    private KdcRequest getKdcRequest( KerberosPrincipal clientPrincipal, String password, KdcControls controls )
        throws IOException
    {
        RequestBodyModifier modifier = new RequestBodyModifier();

        // TODO - set enc type base on contols
        KerberosKey kerberosKey = new KerberosKey( clientPrincipal, password.toCharArray(), "DES" );
        clientKey = new EncryptionKey( EncryptionType.DES_CBC_MD5, kerberosKey.getEncoded() );

        /*
         Forwardable Ticket false
         Forwarded Ticket false
         Proxiable Ticket false
         Proxy Ticket false
         Postdated Ticket false
         Renewable Ticket false
         Initial Ticket false
         */
        KdcOptions kdcOptions = new KdcOptions();

        PreAuthenticationData[] paData = new PreAuthenticationData[1];

        if ( controls.isUsePaEncTimestamp() )
        {
            CipherTextHandler lockBox = new CipherTextHandler();

            KerberosTime timeStamp = new KerberosTime();
            EncryptedTimeStamp encryptedTimeStamp = new EncryptedTimeStamp( timeStamp, 0 );

            EncryptedData encryptedData = null;

            try
            {
                encryptedData = lockBox.seal( clientKey, encryptedTimeStamp, KeyUsage.NUMBER1 );
            }
            catch ( KerberosException ke )
            {
                log.error( "Unexpected exception sealing encrypted timestamp.", ke );
            }

            byte[] encodedEncryptedData = EncryptedDataEncoder.encode( encryptedData );

            PreAuthenticationDataModifier preAuth = new PreAuthenticationDataModifier();
            preAuth.setDataType( PreAuthenticationDataType.PA_ENC_TIMESTAMP );
            preAuth.setDataValue( encodedEncryptedData );

            paData[0] = preAuth.getPreAuthenticationData();
        }

        PrincipalName clientName = new PrincipalName( clientPrincipal.getName(), clientPrincipal.getNameType() );
        modifier.setClientName( clientName );
        modifier.setRealm( clientPrincipal.getRealm() );

        PrincipalName serverName = new PrincipalName( "krbtgt/" + clientPrincipal.getRealm(), clientPrincipal
            .getNameType() );
        modifier.setServerName( serverName );

        if ( kdcOptions.get( KdcOptions.POSTDATED ) )
        {
            // body.from := requested starting time;
        }

        long currentTime = System.currentTimeMillis();

        KerberosTime endTime = new KerberosTime( currentTime + KdcControls.DAY );
        modifier.setTill( endTime );

        if ( kdcOptions.get( KdcOptions.RENEWABLE ) )
        {
            KerberosTime rTime = new KerberosTime( currentTime + KdcControls.WEEK );
            modifier.setRtime( rTime );
        }

        modifier.setKdcOptions( kdcOptions );

        modifier.setNonce( random.nextInt() );

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

        int pvno = 5;
        MessageType messageType = MessageType.KRB_AS_REQ;

        return new KdcRequest( pvno, messageType, paData, requestBody );
    }


    private IoConnector getConnector( String transport )
    {
        IoConnector connector;

        if ( transport.equals( "UDP" ) )
        {
            connector = new DatagramConnector();
        }
        else
        {
            connector = new SocketConnector();
        }

        return connector;
    }
}