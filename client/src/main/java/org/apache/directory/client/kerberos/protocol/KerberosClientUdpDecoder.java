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


import java.io.IOException;

import org.apache.directory.server.kerberos.shared.io.decoder.ErrorMessageDecoder;
import org.apache.directory.server.kerberos.shared.io.decoder.KdcReplyDecoder;
import org.apache.mina.common.ByteBuffer;
import org.apache.mina.common.IoSession;
import org.apache.mina.filter.codec.ProtocolDecoderAdapter;
import org.apache.mina.filter.codec.ProtocolDecoderOutput;


/**
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev: 502788 $, $Date: 2007-02-02 15:11:29 -0800 (Fri, 02 Feb 2007) $
 */
public class KerberosClientUdpDecoder extends ProtocolDecoderAdapter
{
    private static final byte ERROR = ( byte ) 0x7E;

    private KdcReplyDecoder replyDecoder = new KdcReplyDecoder();
    private ErrorMessageDecoder errorDecoder = new ErrorMessageDecoder();


    public void decode( IoSession session, ByteBuffer in, ProtocolDecoderOutput out ) throws IOException
    {
        byte header = in.get();
        in.rewind();

        if ( header == ERROR )
        {
            out.write( errorDecoder.decode( in.buf() ) );
        }
        else
        {
            out.write( replyDecoder.decode( in.buf() ) );
        }
    }
}
