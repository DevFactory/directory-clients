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
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;

import org.apache.directory.client.kerberos.protocol.KerberosClientHandler;
import org.apache.directory.server.kerberos.shared.KerberosConstants;
import org.apache.directory.server.kerberos.shared.KerberosMessageType;
import org.apache.directory.server.kerberos.shared.crypto.checksum.ChecksumHandler;
import org.apache.directory.server.kerberos.shared.crypto.checksum.ChecksumType;
import org.apache.directory.server.kerberos.shared.crypto.encryption.CipherTextHandler;
import org.apache.directory.server.kerberos.shared.crypto.encryption.EncryptionType;
import org.apache.directory.server.kerberos.shared.crypto.encryption.KeyUsage;
import org.apache.directory.server.kerberos.shared.exceptions.KerberosException;
import org.apache.directory.server.kerberos.shared.io.decoder.TicketDecoder;
import org.apache.directory.server.kerberos.shared.io.encoder.ApplicationRequestEncoder;
import org.apache.directory.server.kerberos.shared.io.encoder.KdcRequestEncoder;
import org.apache.directory.server.kerberos.shared.io.encoder.TicketEncoder;
import org.apache.directory.server.kerberos.shared.messages.ApplicationRequest;
import org.apache.directory.server.kerberos.shared.messages.ErrorMessage;
import org.apache.directory.server.kerberos.shared.messages.KdcReply;
import org.apache.directory.server.kerberos.shared.messages.KdcRequest;
import org.apache.directory.server.kerberos.shared.messages.components.Authenticator;
import org.apache.directory.server.kerberos.shared.messages.components.AuthenticatorModifier;
import org.apache.directory.server.kerberos.shared.messages.components.EncKdcRepPart;
import org.apache.directory.server.kerberos.shared.messages.components.Ticket;
import org.apache.directory.server.kerberos.shared.messages.value.ApOptions;
import org.apache.directory.server.kerberos.shared.messages.value.Checksum;
import org.apache.directory.server.kerberos.shared.messages.value.EncryptedData;
import org.apache.directory.server.kerberos.shared.messages.value.EncryptionKey;
import org.apache.directory.server.kerberos.shared.messages.value.KdcOptions;
import org.apache.directory.server.kerberos.shared.messages.value.KerberosTime;
import org.apache.directory.server.kerberos.shared.messages.value.PaData;
import org.apache.directory.server.kerberos.shared.messages.value.PrincipalName;
import org.apache.directory.server.kerberos.shared.messages.value.RequestBody;
import org.apache.directory.server.kerberos.shared.messages.value.RequestBodyModifier;
import org.apache.directory.server.kerberos.shared.messages.value.flags.TicketFlag;
import org.apache.directory.server.kerberos.shared.messages.value.flags.TicketFlags;
import org.apache.directory.server.kerberos.shared.messages.value.types.PaDataType;
import org.apache.mina.common.ConnectFuture;
import org.apache.mina.common.IoConnector;
import org.apache.mina.common.IoSession;
import org.apache.mina.transport.socket.nio.DatagramConnector;
import org.apache.mina.transport.socket.nio.SocketConnector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A command object for requesting a Kerberos service ticket.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class GetServiceTicket
{
    private static final Logger log = LoggerFactory.getLogger( GetServiceTicket.class );

    private static final SecureRandom random = new SecureRandom();

    private static final CipherTextHandler cipherTextHandler = new CipherTextHandler();

    /** The remote Kerberos server name. */
    private String hostname;

    /** The remote Kerberos server port. */
    private int port;

    /** The Kerberos transport. */
    private String transport;

    /** Session attributes that must be verified. */
    private EncryptionKey sessionKey;
    private EncryptionKey subSessionKey;
    private int sequenceNumber;
    private KerberosTime now;


    /**
     * Creates a new instance of GetServiceTicket.
     *
     * @param hostname
     * @param port 
     * @param transport
     */
    public GetServiceTicket( String hostname, int port, String transport )
    {
        this.hostname = hostname;
        this.port = port;
        this.transport = transport;
    }


    /**
     * Execute the request for a service ticket.
     * 
     * @param tgt 
     * @param servicePrincipal 
     * @param controls 
     * @return The service ticket.
     * @throws KdcConnectionException 
     */
    public KerberosTicket execute( KerberosTicket tgt, KerberosPrincipal servicePrincipal, KdcControls controls )
        throws KdcConnectionException
    {
        IoConnector connector = getConnector( transport );

        ConnectFuture future = connector.connect( new InetSocketAddress( hostname, port ), new KerberosClientHandler() );

        future.join();

        IoSession session = future.getSession();

        try
        {
            KdcRequest request = getKdcRequest( tgt, servicePrincipal, controls );
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

        throw new KdcConnectionException( errorText, errorCode );
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
            // TODO - could have used sub-session key to seal, if sub-session key set in authenticator.
            repPart = ( EncKdcRepPart ) cipherTextHandler.unseal( EncKdcRepPart.class, sessionKey, encRepPart,
                KeyUsage.NUMBER8 );
        }
        catch ( KerberosException ke )
        {
            log.debug( "Unexpected exception.", ke );
            return null;
        }

        byte[] sessionKey = repPart.getKey().getKeyValue();
        int keyType = repPart.getKey().getKeyType().getOrdinal();

        Date authTime = repPart.getAuthTime().toDate();
        Date startTime = ( repPart.getStartTime() != null ) ? repPart.getStartTime().toDate() : null; // optional
        Date endTime = repPart.getEndTime().toDate();
        Date renewTill = ( repPart.getRenewTill() != null ) ? repPart.getRenewTill().toDate() : null; // optional

        TicketFlags ticketFlags = repPart.getFlags();

        boolean[] flags = new boolean[TicketFlag.MAX_VALUE.getOrdinal()];

        for ( int i = 0; i < TicketFlag.MAX_VALUE.getOrdinal(); i++ )
        {
            flags[i] = ticketFlags.isFlagSet( i );
        }

        InetAddress[] clientAddresses = null;

        return new KerberosTicket( ticketBytes, client, server, sessionKey, keyType, flags, authTime, startTime,
            endTime, renewTill, clientAddresses );
    }


    /**
     * Create a KdcRequest, suitable for requesting a service Ticket.
     * 
     * Based on RFC 1510, A.5.  KRB_TGS_REQ generation
     */
    private KdcRequest getKdcRequest( KerberosTicket tgt, KerberosPrincipal servicePrincipal, KdcControls controls )
        throws Exception
    {
        // Get the session key from the service ticket.
        byte[] sessionKeyBytes = tgt.getSessionKey().getEncoded();
        int keyType = tgt.getSessionKeyType();

        sessionKey = new EncryptionKey( EncryptionType.getTypeByOrdinal( keyType ), sessionKeyBytes );

        RequestBodyModifier modifier = new RequestBodyModifier();

        /*
         If the TGT is not for the realm of the end-server
         then the sname will be for a TGT for the end-realm
         and the realm of the requested ticket (body.realm)
         will be that of the TGS to which the TGT we are
         sending applies.
         */
        PrincipalName serverName = new PrincipalName( servicePrincipal.getName(), servicePrincipal.getNameType() );
        modifier.setServerName( serverName );
        modifier.setRealm( servicePrincipal.getRealm() );

        KdcOptions kdcOptions = new KdcOptions();

        // Set the requested starting time.
        if ( controls.getStartTime() != null )
        {
            KerberosTime fromTime = new KerberosTime( controls.getStartTime() );
            modifier.setFrom( fromTime );
            kdcOptions.set( KdcOptions.POSTDATED );
        }

        long currentTime = System.currentTimeMillis();

        KerberosTime endTime = new KerberosTime( currentTime + controls.getLifeTime() );
        modifier.setTill( endTime );

        if ( controls.getRenewableLifetime() > 0 )
        {
            KerberosTime renewTime = new KerberosTime( currentTime + controls.getRenewableLifetime() );
            modifier.setRtime( renewTime );
            kdcOptions.set( KdcOptions.RENEWABLE );
        }

        if ( controls.isProxiable() )
        {
            kdcOptions.set( KdcOptions.PROXIABLE );
        }

        if ( controls.isForwardable() )
        {
            kdcOptions.set( KdcOptions.FORWARDABLE );
        }

        if ( controls.isForwarded() )
        {
            kdcOptions.set( KdcOptions.FORWARDED );
        }

        if ( controls.isProxy() )
        {
            kdcOptions.set( KdcOptions.PROXY );
        }

        modifier.setKdcOptions( kdcOptions );

        modifier.setNonce( random.nextInt() );

        Set<EncryptionType> encryptionTypes = new HashSet<EncryptionType>();
        encryptionTypes.add( EncryptionType.DES_CBC_MD5 );

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

        int pvno = KerberosConstants.KERBEROS_V5;
        KerberosMessageType messageType = KerberosMessageType.TGS_REQ;

        KdcRequestEncoder bodyEncoder = new KdcRequestEncoder();
        byte[] bodyBytes = bodyEncoder.encodeRequestBody( requestBody );

        ChecksumHandler checksumHandler = new ChecksumHandler();
        Checksum checksum = checksumHandler.calculateChecksum( ChecksumType.RSA_MD5, bodyBytes, null, KeyUsage.NUMBER8 );

        PaData[] paData = new PaData[1];

        PaData preAuth = new PaData();
        preAuth.setPaDataType( PaDataType.PA_TGS_REQ );

        // Generate a new sequence number.
        sequenceNumber = random.nextInt();

        now = new KerberosTime();

        EncryptedData authenticator = getAuthenticator( tgt.getClient(), checksum );
        Ticket convertedTicket = TicketDecoder.decode( tgt.getEncoded() );

        // Make new ap req, aka the "auth header."
        ApplicationRequest applicationRequest = new ApplicationRequest();
        applicationRequest.setMessageType( KerberosMessageType.AP_REQ );
        applicationRequest.setProtocolVersionNumber( 5 );
        applicationRequest.setApOptions( new ApOptions() );
        applicationRequest.setTicket( convertedTicket );
        applicationRequest.setEncPart( authenticator );

        ApplicationRequestEncoder encoder = new ApplicationRequestEncoder();
        byte[] encodedApReq = encoder.encode( applicationRequest );

        preAuth.setPaDataValue( encodedApReq );

        paData[0] = preAuth;

        return new KdcRequest( pvno, messageType, paData, requestBody );
    }


    /**
     * Build the authenticator.  The authenticator communicates the sub-session key the
     * service will use to unlock the private message.  The service will unlock the
     * authenticator with the session key from the ticket.  The authenticator client
     * principal must equal the principal in the ticket.  
     *
     * @param clientPrincipal
     * @return The {@link EncryptedData} containing the {@link Authenticator}.
     * @throws KerberosException
     */
    private EncryptedData getAuthenticator( KerberosPrincipal clientPrincipal, Checksum checksum )
        throws KerberosException
    {
        AuthenticatorModifier authenticatorModifier = new AuthenticatorModifier();

        authenticatorModifier.setVersionNumber( 5 );
        authenticatorModifier.setClientPrincipal( clientPrincipal );
        authenticatorModifier.setClientTime( now );
        authenticatorModifier.setClientMicroSecond( 0 );
        authenticatorModifier.setSubSessionKey( subSessionKey );
        authenticatorModifier.setSequenceNumber( sequenceNumber );
        authenticatorModifier.setChecksum( checksum );

        Authenticator authenticator = authenticatorModifier.getAuthenticator();

        EncryptedData encryptedAuthenticator = cipherTextHandler.seal( sessionKey, authenticator, KeyUsage.NUMBER11 );

        return encryptedAuthenticator;
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
