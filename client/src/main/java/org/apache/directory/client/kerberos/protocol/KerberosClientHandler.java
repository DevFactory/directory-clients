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
package org.apache.directory.client.kerberos.protocol;


import org.apache.directory.server.kerberos.shared.messages.ErrorMessage;
import org.apache.directory.server.kerberos.shared.messages.KdcReply;
import org.apache.mina.common.IdleStatus;
import org.apache.mina.common.IoHandler;
import org.apache.mina.common.IoHandlerAdapter;
import org.apache.mina.common.IoSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * An {@link IoHandler} implementation for a Kerberos client.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class KerberosClientHandler extends IoHandlerAdapter
{
    private static final Logger log = LoggerFactory.getLogger( KerberosClientHandler.class );


    public void sessionCreated( IoSession session ) throws Exception
    {
        if ( log.isDebugEnabled() )
        {
            log.debug( session.getRemoteAddress() + " CREATED" );
        }
    }


    public void sessionOpened( IoSession session )
    {
        if ( log.isDebugEnabled() )
        {
            log.debug( session.getRemoteAddress() + " OPENED" );
        }
    }


    public void sessionClosed( IoSession session )
    {
        if ( log.isDebugEnabled() )
        {
            log.debug( session.getRemoteAddress() + " CLOSED" );
        }
    }


    public void sessionIdle( IoSession session, IdleStatus status )
    {
        if ( log.isDebugEnabled() )
        {
            log.debug( session.getRemoteAddress() + " IDLE(" + status + ")" );
        }
    }


    public void messageReceived( IoSession session, Object message )
    {
        if ( log.isDebugEnabled() )
        {
            log.debug( session.getRemoteAddress() + " RCVD: " + message );
        }

        System.out.println( session.getRemoteAddress() + " RCVD: " + message );

        if ( message instanceof KdcReply )
        {
            KdcReply reply = ( KdcReply ) message;
            System.out.println( reply.getClientRealm() );
        }
        else
        {
            if ( message instanceof ErrorMessage )
            {
                ErrorMessage error = ( ErrorMessage ) message;
                System.out.println( error.getExplanatoryText() );
            }
        }

        session.close();
    }


    public void messageSent( IoSession session, Object message )
    {
        if ( log.isDebugEnabled() )
        {
            log.debug( session.getRemoteAddress() + " SENT: " + message );
        }

        System.out.println( session.getRemoteAddress() + " SENT: " + message );
    }


    public void exceptionCaught( IoSession session, Throwable cause )
    {
        log.error( session.getRemoteAddress() + " EXCEPTION", cause );

        System.out.println( session.getRemoteAddress() + " EXCEPTION" );

        cause.printStackTrace();

        session.close();
    }
}
