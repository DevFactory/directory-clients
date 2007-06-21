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


import org.apache.directory.server.changepw.io.ChangePasswordErrorDecoder;
import org.apache.directory.server.changepw.io.ChangePasswordReplyDecoder;
import org.apache.mina.common.BufferDataException;
import org.apache.mina.common.ByteBuffer;
import org.apache.mina.common.IoSession;
import org.apache.mina.filter.codec.CumulativeProtocolDecoder;
import org.apache.mina.filter.codec.ProtocolDecoderOutput;


/**
 * A {@link CumulativeProtocolDecoder} which supports Set/Change Password client
 * operation over TCP, by reassembling split packets prior to ASN.1 DER decoding.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class PasswordClientTcpDecoder extends CumulativeProtocolDecoder
{
    private static final short ERROR = 0;

    private ChangePasswordReplyDecoder replyDecoder = new ChangePasswordReplyDecoder();
    private ChangePasswordErrorDecoder errorDecoder = new ChangePasswordErrorDecoder();

    private int maxObjectSize = 16384; // 16KB


    /**
     * Returns the allowed maximum size of the object to be decoded.
     * If the size of the object to be decoded exceeds this value, this
     * decoder will throw a {@link BufferDataException}.  The default
     * value is <tt>16384</tt> (16KB).
     * 
     * @return The max object size.
     */
    public int getMaxObjectSize()
    {
        return maxObjectSize;
    }


    /**
     * Sets the allowed maximum size of the object to be decoded.
     * If the size of the object to be decoded exceeds this value, this
     * decoder will throw a {@link BufferDataException}.  The default
     * value is <tt>16384</tt> (16KB).
     * 
     * @param maxObjectSize 
     */
    public void setMaxObjectSize( int maxObjectSize )
    {
        if ( maxObjectSize <= 0 )
        {
            throw new IllegalArgumentException( "maxObjectSize: " + maxObjectSize );
        }

        this.maxObjectSize = maxObjectSize;
    }


    @Override
    protected boolean doDecode( IoSession session, ByteBuffer in, ProtocolDecoderOutput out ) throws Exception
    {
        if ( !in.prefixedDataAvailable( 4, maxObjectSize ) )
        {
            return false;
        }

        in.getInt();

        // read message length
        in.getShort();

        // read version
        in.getShort();

        // read AP_REQ length
        short header = in.getShort();
        in.rewind();

        if ( header == ERROR )
        {
            out.write( errorDecoder.decode( in.buf() ) );
        }
        else
        {
            out.write( replyDecoder.decode( in.buf() ) );
        }

        return true;
    }
}
