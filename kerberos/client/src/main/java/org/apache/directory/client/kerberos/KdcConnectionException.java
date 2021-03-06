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


/**
 * The root of the {@link KdcConnection} exception hierarchy.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class KdcConnectionException extends Exception
{
    /** 
     * The class fingerprint that is set to indicate serialization
     * compatibility with a previous version of the class.
     */
    private static final long serialVersionUID = -3882166764471452526L;

    /**
     * The Kerberos error code associated with this exception.
     */
    private int errorCode = 0;


    /**
     * @param message
     */
    public KdcConnectionException( String message )
    {
        super( message );
    }


    /**
     * @param message
     * @param errorCode
     */
    public KdcConnectionException( String message, int errorCode )
    {
        super( message );
        this.errorCode = errorCode;
    }


    /**
     * @param cause
     */
    public KdcConnectionException( Throwable cause )
    {
        super( cause );
    }


    /**
     * @param message
     * @param cause
     */
    public KdcConnectionException( String message, Throwable cause )
    {
        super( message, cause );
    }


    /**
     * Gets the protocol error code associated with this {@link KdcConnectionException}.
     *
     * @return The error code associated with this {@link KdcConnectionException}.
     */
    public int getErrorCode()
    {
        return this.errorCode;
    }


    public String getMessage()
    {
        return super.getMessage() + " (" + errorCode + ")";
    }
}
