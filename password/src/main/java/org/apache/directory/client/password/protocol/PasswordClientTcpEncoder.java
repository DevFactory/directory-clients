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

import org.apache.directory.server.changepw.io.ChangePasswordRequestEncoder;
import org.apache.directory.server.changepw.messages.ChangePasswordRequest;
import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.ProtocolEncoderAdapter;
import org.apache.mina.filter.codec.ProtocolEncoderOutput;


/**
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class PasswordClientTcpEncoder extends ProtocolEncoderAdapter
{
    private ChangePasswordRequestEncoder requestEncoder = new ChangePasswordRequestEncoder();


    public void encode( IoSession session, Object message, ProtocolEncoderOutput out ) throws IOException
    {
        IoBuffer buf = IoBuffer.allocate( 1024 );

        // make space for int length
        buf.putInt( 0 );

        requestEncoder.encode( buf.buf(), ( ChangePasswordRequest ) message );

        // mark position
        int end = buf.position();

        // length is the data minus 4 bytes for the pre-pended length
        int recordLength = end - 4;

        // write the length
        buf.rewind();
        buf.putInt( recordLength );

        // set the position back before flipping the buffer
        buf.position( end );
        buf.flip();

        out.write( buf );
    }
}
