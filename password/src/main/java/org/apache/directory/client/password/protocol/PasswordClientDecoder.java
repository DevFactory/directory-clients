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


import java.io.IOException;
import java.util.Arrays;

import org.apache.directory.server.changepw.io.ChangePasswordReplyDecoder;
import org.apache.directory.server.kerberos.shared.io.decoder.ErrorMessageDecoder;
import org.apache.mina.common.ByteBuffer;
import org.apache.mina.common.IoSession;
import org.apache.mina.filter.codec.ProtocolDecoderAdapter;
import org.apache.mina.filter.codec.ProtocolDecoderOutput;


/**
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class PasswordClientDecoder extends ProtocolDecoderAdapter
{
    private static final byte[] ERROR = new byte[]
        { ( byte ) 0x7E, ( byte ) 0x78, ( byte ) 0x30, ( byte ) 0x76 };

    private ChangePasswordReplyDecoder replyDecoder = new ChangePasswordReplyDecoder();
    private ErrorMessageDecoder errorDecoder = new ErrorMessageDecoder();


    public void decode( IoSession session, ByteBuffer in, ProtocolDecoderOutput out ) throws IOException
    {
        byte[] header = new byte[4];
        in.get( header );
        in.rewind();

        if ( Arrays.equals( ERROR, header ) )
        {
            out.write( errorDecoder.decode( in.buf() ) );
        }
        else
        {
            out.write( replyDecoder.decode( in.buf() ) );
        }
    }
}
