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
import java.util.Date;

import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;

import org.apache.directory.client.password.protocol.PasswordClientCodecFactory;
import org.apache.directory.client.password.protocol.PasswordClientHandler;
import org.apache.directory.server.changepw.messages.ChangePasswordReply;
import org.apache.directory.server.changepw.messages.ChangePasswordRequest;
import org.apache.directory.server.changepw.messages.ChangePasswordRequestModifier;
import org.apache.directory.server.kerberos.shared.crypto.encryption.CipherTextHandler;
import org.apache.directory.server.kerberos.shared.crypto.encryption.EncryptionType;
import org.apache.directory.server.kerberos.shared.crypto.encryption.KeyUsage;
import org.apache.directory.server.kerberos.shared.crypto.encryption.RandomKeyFactory;
import org.apache.directory.server.kerberos.shared.exceptions.KerberosException;
import org.apache.directory.server.kerberos.shared.messages.ApplicationRequest;
import org.apache.directory.server.kerberos.shared.messages.MessageType;
import org.apache.directory.server.kerberos.shared.messages.application.ApplicationReply;
import org.apache.directory.server.kerberos.shared.messages.application.PrivateMessage;
import org.apache.directory.server.kerberos.shared.messages.components.Authenticator;
import org.apache.directory.server.kerberos.shared.messages.components.AuthenticatorModifier;
import org.apache.directory.server.kerberos.shared.messages.components.EncApRepPart;
import org.apache.directory.server.kerberos.shared.messages.components.EncKrbPrivPart;
import org.apache.directory.server.kerberos.shared.messages.components.EncKrbPrivPartModifier;
import org.apache.directory.server.kerberos.shared.messages.components.EncTicketPart;
import org.apache.directory.server.kerberos.shared.messages.components.EncTicketPartModifier;
import org.apache.directory.server.kerberos.shared.messages.components.Ticket;
import org.apache.directory.server.kerberos.shared.messages.components.TicketModifier;
import org.apache.directory.server.kerberos.shared.messages.value.ApOptions;
import org.apache.directory.server.kerberos.shared.messages.value.EncryptedData;
import org.apache.directory.server.kerberos.shared.messages.value.EncryptionKey;
import org.apache.directory.server.kerberos.shared.messages.value.HostAddress;
import org.apache.directory.server.kerberos.shared.messages.value.KerberosTime;
import org.apache.directory.server.kerberos.shared.messages.value.TicketFlags;
import org.apache.directory.server.kerberos.shared.messages.value.TransitedEncoding;
import org.apache.directory.shared.ldap.util.StringTools;
import org.apache.mina.common.ConnectFuture;
import org.apache.mina.common.IoConnector;
import org.apache.mina.common.IoSession;
import org.apache.mina.filter.LoggingFilter;
import org.apache.mina.filter.codec.ProtocolCodecFilter;
import org.apache.mina.transport.socket.nio.DatagramConnector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A command-line client for changing passwords.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class ChangePassword
{
    private static final Logger log = LoggerFactory.getLogger( ChangePassword.class );

    private static final SecureRandom random = new SecureRandom();

    /** The remote Change Password server name. */
    private String hostname = "localhost";

    /** The remote ChangePassword port number. */
    private static final int REMOTE_PORT = 464;

    /** One day in milliseconds, used for default end time. */
    private static final int ONE_DAY = 86400000;

    /** One week in milliseconds, used for default renewal period. */
    private static final int ONE_WEEK = 86400000 * 7;

    private CipherTextHandler cipherTextHandler = new CipherTextHandler();

    private EncryptionKey sessionKey;
    private EncryptionKey subSessionKey;


    /**
     * Change a password.
     * 
     * @param args
     * @throws Exception
     */
    public static void main( String[] args ) throws Exception
    {
        new ChangePassword().go();
    }


    /**
     * Make the request to change a password.
     */
    public void go()
    {
        try
        {
            sessionKey = RandomKeyFactory.getRandomKey( EncryptionType.DES_CBC_MD5 );
            subSessionKey = RandomKeyFactory.getRandomKey( EncryptionType.DES_CBC_MD5 );
        }
        catch ( KerberosException ke )
        {
            log.debug( "Unexpected exception.", ke );
        }

        IoConnector connector = new DatagramConnector();

        connector.getFilterChain()
            .addLast( "codec", new ProtocolCodecFilter( PasswordClientCodecFactory.getInstance() ) );
        connector.getFilterChain().addLast( "logger", new LoggingFilter() );

        ConnectFuture future = connector.connect( new InetSocketAddress( hostname, REMOTE_PORT ),
            new PasswordClientHandler() );

        future.join();

        IoSession session = future.getSession();

        try
        {
            ChangePasswordRequest request = getChangePasswordRequest();
            session.write( request );
        }
        catch ( Exception e )
        {
            log.debug( "Unexpected exception.", e );
        }

        session.getCloseFuture().join();

        ChangePasswordReply reply = ( ChangePasswordReply ) session.getAttribute( "reply" );
        processChangePasswordReply( reply );
    }


    private void processChangePasswordReply( ChangePasswordReply reply )
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

        // The response user-data contains a result code.
        byte[] resultCode = privPart.getUserData();
        HostAddress address = privPart.getSenderAddress();

        log.debug( StringTools.dumpBytes( resultCode ) );
        log.debug( address.toString() );

        log.debug( repPart.getClientTime().toString() );
        log.debug( Integer.toString( repPart.getClientMicroSecond() ) );
        log.debug( repPart.getSequenceNumber().toString() ); // authenticator.getSequenceNumber()
        log.debug( repPart.getSubSessionKey().toString() ); // authenticator.getSubSessionKey()
    }


    /**
     * Create a {@link ChangePasswordRequest}.
     */
    private ChangePasswordRequest getChangePasswordRequest() throws Exception
    {
        // TODO - parameterize
        KerberosPrincipal clientPrincipal = new KerberosPrincipal( "hnelson@EXAMPLE.COM" );
        KerberosPrincipal serverPrincipal = new KerberosPrincipal( "kadmin/changepw@EXAMPLE.COM" );
        String newPassword = "cabletr0N";

        // TODO - serverKey comes from store or store ticket.
        KerberosKey serverKerberosKey = new KerberosKey( serverPrincipal, "s3crEt".toCharArray(), "DES" );
        byte[] serverKeyBytes = serverKerberosKey.getEncoded();
        EncryptionKey serverKey = new EncryptionKey( EncryptionType.DES_CBC_MD5, serverKeyBytes );

        // Build Change Password request.
        ChangePasswordRequestModifier modifier = new ChangePasswordRequestModifier();

        Ticket ticket = getTicket( clientPrincipal, serverPrincipal, serverKey );
        EncryptedData authenticator = getAuthenticator( clientPrincipal );

        // TODO - move
        KerberosTicket kerberosTicket = getKerberosTicket( ticket );

        // Make new ap req, aka the "auth header."
        ApplicationRequest applicationRequest = new ApplicationRequest();
        applicationRequest.setMessageType( MessageType.KRB_AP_REQ );
        applicationRequest.setProtocolVersionNumber( 5 );
        applicationRequest.setApOptions( new ApOptions() );
        applicationRequest.setTicket( ticket );
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
        privateMessage.setProtocolVersionNumber( 5 );
        privateMessage.setMessageType( MessageType.ENC_PRIV_PART );
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
        authenticatorModifier.setClientTime( new KerberosTime() );
        authenticatorModifier.setClientMicroSecond( 0 );
        authenticatorModifier.setSubSessionKey( subSessionKey );
        authenticatorModifier.setSequenceNumber( random.nextInt() );

        Authenticator authenticator = authenticatorModifier.getAuthenticator();

        EncryptedData encryptedAuthenticator = cipherTextHandler.seal( sessionKey, authenticator, KeyUsage.NUMBER11 );

        return encryptedAuthenticator;
    }


    /**
     * Build the service ticket.  The service ticket contains the session key generated
     * by the KDC for the client and service to use.  The service will unlock the
     * authenticator with the session key from the ticket.  The principal in the ticket
     * must equal the authenticator client principal.
     * 
     * If set in the AP Options, the Ticket can also be sealed with the session key.
     * 
     * TODO - Allow configurable end time.
     * TODO - Support postdating by setting {@link EncTicketPartModifier#setStartTime(KerberosTime)}.
     * TODO - Support renewal by setting {@link EncTicketPartModifier#setRenewTill(KerberosTime)}.
     * 
     * @param clientPrincipal
     * @param serverPrincipal
     * @return The {@link Ticket}.
     * @throws KerberosException
     */
    private Ticket getTicket( KerberosPrincipal clientPrincipal, KerberosPrincipal serverPrincipal,
        EncryptionKey serverKey ) throws KerberosException
    {
        EncTicketPartModifier encTicketModifier = new EncTicketPartModifier();

        encTicketModifier.setFlags( new TicketFlags() );
        encTicketModifier.setSessionKey( sessionKey );
        encTicketModifier.setClientPrincipal( clientPrincipal );
        encTicketModifier.setTransitedEncoding( new TransitedEncoding() );
        encTicketModifier.setAuthTime( new KerberosTime() );

        KerberosTime endTime = new KerberosTime( System.currentTimeMillis() + ONE_DAY );
        encTicketModifier.setEndTime( endTime );

        EncTicketPart encTicketPart = encTicketModifier.getEncTicketPart();

        EncryptedData encryptedTicketPart = cipherTextHandler.seal( serverKey, encTicketPart, KeyUsage.NUMBER2 );

        TicketModifier ticketModifier = new TicketModifier();
        ticketModifier.setTicketVersionNumber( 5 );
        ticketModifier.setServerPrincipal( serverPrincipal );
        ticketModifier.setEncPart( encryptedTicketPart );

        Ticket ticket = ticketModifier.getTicket();

        ticket.setEncTicketPart( encTicketPart );

        return ticket;
    }


    /**
     * Convert an Apache Directory Kerberos {@link Ticket} into a {@link KerberosTicket}.
     *
     * @param ticket
     * @return The {@link KerberosTicket}.
     */
    private KerberosTicket getKerberosTicket( Ticket ticket )
    {
        byte[] asn1Encoding = new byte[( byte ) 0x00];
        KerberosPrincipal client = ticket.getClientPrincipal();
        KerberosPrincipal server = ticket.getServerPrincipal();
        byte[] sessionKey = ticket.getSessionKey().getKeyValue();
        int keyType = ticket.getSessionKey().getKeyType().getOrdinal();

        // TODO - adapt flags
        boolean[] flags = new boolean[0];

        Date authTime = ticket.getAuthTime().toDate();
        Date endTime = ticket.getEndTime().toDate();

        Date startTime = ( ticket.getStartTime() != null ? ticket.getStartTime().toDate() : null );

        Date renewTill = null;

        if ( ticket.getFlag( TicketFlags.RENEWABLE ) )
        {
            renewTill = ( ticket.getRenewTill() != null ? ticket.getRenewTill().toDate() : null );
        }

        InetAddress[] clientAddresses = new InetAddress[0];

        return new KerberosTicket( asn1Encoding, client, server, sessionKey, keyType, flags, authTime, startTime,
            endTime, renewTill, clientAddresses );
    }
}
