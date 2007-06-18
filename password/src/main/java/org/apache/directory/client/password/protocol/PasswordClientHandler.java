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
package org.apache.directory.client.password.protocol;


import org.apache.directory.server.changepw.messages.ChangePasswordReply;
import org.apache.directory.server.kerberos.shared.messages.ErrorMessage;
import org.apache.mina.common.IoHandler;
import org.apache.mina.common.IoHandlerAdapter;
import org.apache.mina.common.IoSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * An {@link IoHandler} implementation for a Set/Change Password client.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class PasswordClientHandler extends IoHandlerAdapter
{
    private static final Logger log = LoggerFactory.getLogger( PasswordClientHandler.class );


    public void messageReceived( IoSession session, Object message )
    {
        if ( message instanceof ChangePasswordReply )
        {
            ChangePasswordReply reply = ( ChangePasswordReply ) message;
            session.setAttribute( "reply", reply );
        }
        else
        {
            if ( message instanceof ErrorMessage )
            {
                ErrorMessage error = ( ErrorMessage ) message;
                log.debug( error.getExplanatoryText() );
            }
        }

        session.close();
    }


    public void exceptionCaught( IoSession session, Throwable cause )
    {
        log.error( session.getRemoteAddress() + " EXCEPTION", cause );

        session.close();
    }
}
