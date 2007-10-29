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


import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;

import org.apache.directory.client.password.protocol.PasswordClientHandler;
import org.apache.directory.server.changepw.messages.ChangePasswordError;
import org.apache.directory.server.changepw.messages.ChangePasswordReply;
import org.apache.directory.server.changepw.messages.ChangePasswordRequest;
import org.apache.directory.server.changepw.messages.ChangePasswordRequestModifier;
import org.apache.directory.server.kerberos.shared.KerberosConstants;
import org.apache.directory.server.kerberos.shared.KerberosMessageType;
import org.apache.directory.server.kerberos.shared.crypto.encryption.CipherTextHandler;
import org.apache.directory.server.kerberos.shared.crypto.encryption.EncryptionType;
import org.apache.directory.server.kerberos.shared.crypto.encryption.KeyUsage;
import org.apache.directory.server.kerberos.shared.crypto.encryption.RandomKeyFactory;
import org.apache.directory.server.kerberos.shared.exceptions.KerberosException;
import org.apache.directory.server.kerberos.shared.io.decoder.TicketDecoder;
import org.apache.directory.server.kerberos.shared.messages.ApplicationRequest;
import org.apache.directory.server.kerberos.shared.messages.ErrorMessage;
import org.apache.directory.server.kerberos.shared.messages.application.ApplicationReply;
import org.apache.directory.server.kerberos.shared.messages.application.PrivateMessage;
import org.apache.directory.server.kerberos.shared.messages.components.Authenticator;
import org.apache.directory.server.kerberos.shared.messages.components.AuthenticatorModifier;
import org.apache.directory.server.kerberos.shared.messages.components.EncApRepPart;
import org.apache.directory.server.kerberos.shared.messages.components.EncKrbPrivPart;
import org.apache.directory.server.kerberos.shared.messages.components.EncKrbPrivPartModifier;
import org.apache.directory.server.kerberos.shared.messages.components.Ticket;
import org.apache.directory.server.kerberos.shared.messages.value.ApOptions;
import org.apache.directory.server.kerberos.shared.messages.value.EncryptedData;
import org.apache.directory.server.kerberos.shared.messages.value.EncryptionKey;
import org.apache.directory.server.kerberos.shared.messages.value.HostAddress;
import org.apache.directory.server.kerberos.shared.messages.value.KerberosTime;
import org.apache.mina.common.ConnectFuture;
import org.apache.mina.common.IoConnector;
import org.apache.mina.common.IoSession;
import org.apache.mina.transport.socket.nio.DatagramConnector;
import org.apache.mina.transport.socket.nio.SocketConnector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A command object for changing the password of a target principal.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class ChangePassword
{
    private static final Logger log = LoggerFactory.getLogger( ChangePassword.class );

    private static final SecureRandom random = new SecureRandom();

    private static final CipherTextHandler cipherTextHandler = new CipherTextHandler();

    /** The Change Password SUCCESS result code. */
    private static final byte[] SUCCESS = new byte[]
        { ( byte ) 0x00, ( byte ) 0x00 };

    /** The remote Change Password server name. */
    private String hostname;

    /** The remote Change Password server port. */
    private int port;

    /** The Change Password transport. */
    private String transport;

    private EncryptionKey sessionKey;
    private EncryptionKey subSessionKey;
    private int sequenceNumber;
    private KerberosTime now;


    /**
     * Creates a new instance of ChangePassword.
     *
     * @param hostname
     * @param port 
     * @param transport
     */
    public ChangePassword( String hostname, int port, String transport )
    {
        this.hostname = hostname;
        this.port = port;
        this.transport = transport;
    }


    /**
     * Execute the request to change a password.
     * 
     * @param targetPrincipal 
     * @param newPassword 
     * @param serviceTicket 
     * @throws PasswordConnectionException 
     */
    public void execute( KerberosPrincipal targetPrincipal, String newPassword, KerberosTicket serviceTicket )
        throws PasswordConnectionException
    {
        IoConnector connector = getConnector( transport );

        ConnectFuture future = connector.connect( new InetSocketAddress( hostname, port ), new PasswordClientHandler() );

        future.join();

        IoSession session = future.getSession();

        try
        {
            ChangePasswordRequest request = getChangePasswordRequest( targetPrincipal, newPassword, serviceTicket );
            session.write( request );
        }
        catch ( Exception e )
        {
            log.debug( "Unexpected exception.", e );
        }

        session.getCloseFuture().join();

        Object message = session.getAttribute( "reply" );

        if ( message instanceof ChangePasswordReply )
        {
            ChangePasswordReply reply = ( ChangePasswordReply ) message;
            processChangePasswordReply( reply );
        }
        else
        {
            if ( message instanceof ChangePasswordError )
            {
                ChangePasswordError error = ( ChangePasswordError ) message;
                processError( error.getErrorMessage() );
            }
        }
    }


    private void processError( ErrorMessage error ) throws PasswordConnectionException
    {
        int errorCode = error.getErrorCode();
        String errorText = error.getExplanatoryText();

        throw new PasswordConnectionException( errorText + " (" + errorCode + ")" );
    }


    private void processChangePasswordReply( ChangePasswordReply reply ) throws PasswordConnectionException
    {
        PrivateMessage privateMessage = reply.getPrivateMessage();

        EncryptedData encPrivPart = privateMessage.getEncryptedPart();

        EncKrbPrivPart privPart;

        try
        {
            privPart = ( EncKrbPrivPart ) cipherTextHandler.unseal( EncKrbPrivPart.class, subSessionKey, encPrivPart,
                KeyUsage.NUMBER13 );
        }
        catch ( KerberosException ke )
        {
            log.debug( "Unexpected exception.", ke );
            return;
        }

        ApplicationReply appReply = reply.getApplicationReply();
        EncryptedData encRepPart = appReply.getEncPart();

        EncApRepPart repPart;

        try
        {
            repPart = ( EncApRepPart ) cipherTextHandler.unseal( EncApRepPart.class, sessionKey, encRepPart,
                KeyUsage.NUMBER12 );
        }
        catch ( KerberosException ke )
        {
            log.debug( "Unexpected exception.", ke );
            return;
        }

        // Verify result code.
        byte[] resultCode = privPart.getUserData();
        if ( Arrays.equals( SUCCESS, resultCode ) )
        {
            log.info( "Password change returned SUCCESS (0x00 0x00)." );
        }
        else
        {
            throw new PasswordConnectionException( "Password change failed." );
        }

        // Verify client time.
        String replyTime = repPart.getClientTime().toString();
        String sentTime = now.toString();
        if ( !replyTime.equals( sentTime ) )
        {
            log.debug( "Mismatched client time (Expected {}, got {}).", sentTime, replyTime );
            throw new PasswordConnectionException( "Mismatched client time." );
        }

        // Verify sequence number.
        Integer expectedSequence = repPart.getSequenceNumber();
        if ( expectedSequence != sequenceNumber )
        {
            log.error( "Mismatched sequence number (Expected {}, got {}).", sequenceNumber, expectedSequence );
            throw new PasswordConnectionException( "Mismatched sequence number." );
        }
    }


    /**
     * Create a {@link ChangePasswordRequest}.
     */
    private ChangePasswordRequest getChangePasswordRequest( KerberosPrincipal targetPrincipal, String newPassword,
        KerberosTicket serviceTicket ) throws Exception
    {
        // Get the session key from the service ticket.
        byte[] sessionKeyBytes = serviceTicket.getSessionKey().getEncoded();
        int keyType = serviceTicket.getSessionKeyType();

        sessionKey = new EncryptionKey( EncryptionType.getTypeByOrdinal( keyType ), sessionKeyBytes );

        // Generate a new sub-session key.
        try
        {
            EncryptionType encryptionType = EncryptionType.getTypeByOrdinal( keyType );
            subSessionKey = RandomKeyFactory.getRandomKey( encryptionType );
        }
        catch ( KerberosException ke )
        {
            log.debug( "Unexpected exception.", ke );
        }

        // Generate a new sequence number.
        sequenceNumber = random.nextInt( Integer.MAX_VALUE );

        now = new KerberosTime();

        // Build Change Password request.
        ChangePasswordRequestModifier modifier = new ChangePasswordRequestModifier();

        EncryptedData authenticator = getAuthenticator( targetPrincipal );

        Ticket convertedTicket = TicketDecoder.decode( serviceTicket.getEncoded() );

        // Make new ap req, aka the "auth header."
        ApplicationRequest applicationRequest = new ApplicationRequest();
        applicationRequest.setMessageType( KerberosMessageType.AP_REQ );
        applicationRequest.setProtocolVersionNumber( KerberosConstants.KERBEROS_V5 );
        applicationRequest.setApOptions( new ApOptions() );
        applicationRequest.setTicket( convertedTicket );
        applicationRequest.setEncPart( authenticator );

        // Get private message.
        PrivateMessage privateMessage = getPrivateMessage( newPassword );

        modifier.setAuthHeader( applicationRequest );
        modifier.setPrivateMessage( privateMessage );

        return modifier.getChangePasswordMessage();
    }


    /**
     * Build the private message.  The private message contains the user's new password
     * as the "user data."  The private message is sealed with the sub-session key.  The
     * sub-session key is communicated to the service in the authenticator.
     * 
     * @param newPassword
     * @return The {@link PrivateMessage}.
     * @throws UnsupportedEncodingException
     * @throws KerberosException
     * @throws UnknownHostException
     */
    private PrivateMessage getPrivateMessage( String newPassword ) throws UnsupportedEncodingException,
        KerberosException, UnknownHostException
    {
        // Make private message part.
        EncKrbPrivPartModifier privPartModifier = new EncKrbPrivPartModifier();
        privPartModifier.setUserData( newPassword.getBytes( "UTF-8" ) );
        privPartModifier.setSenderAddress( new HostAddress( InetAddress.getLocalHost() ) );
        EncKrbPrivPart encReqPrivPart = privPartModifier.getEncKrbPrivPart();

        // Seal private message part.
        EncryptedData encryptedPrivPart = cipherTextHandler.seal( subSessionKey, encReqPrivPart, KeyUsage.NUMBER13 );

        // Make private message with private message part.
        PrivateMessage privateMessage = new PrivateMessage();
        privateMessage.setProtocolVersionNumber( KerberosConstants.KERBEROS_V5 );
        privateMessage.setMessageType( KerberosMessageType.ENC_PRIV_PART );
        privateMessage.setEncryptedPart( encryptedPrivPart );

        return privateMessage;
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
    private EncryptedData getAuthenticator( KerberosPrincipal clientPrincipal ) throws KerberosException
    {
        AuthenticatorModifier authenticatorModifier = new AuthenticatorModifier();

        authenticatorModifier.setVersionNumber( 5 );
        authenticatorModifier.setClientPrincipal( clientPrincipal );
        authenticatorModifier.setClientTime( now );
        authenticatorModifier.setClientMicroSecond( 0 );
        authenticatorModifier.setSubSessionKey( subSessionKey );
        authenticatorModifier.setSequenceNumber( sequenceNumber );

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
