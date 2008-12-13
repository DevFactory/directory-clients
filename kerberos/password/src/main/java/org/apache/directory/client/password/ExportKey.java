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


import java.io.File;
import java.io.IOException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;

import org.apache.directory.server.kerberos.shared.crypto.encryption.EncryptionType;
import org.apache.directory.server.kerberos.shared.keytab.Keytab;
import org.apache.directory.server.kerberos.shared.keytab.KeytabEntry;
import org.apache.directory.server.kerberos.shared.messages.value.EncryptionKey;
import org.apache.directory.server.kerberos.shared.messages.value.KerberosTime;
import org.apache.directory.server.kerberos.shared.store.PrincipalStoreEntry;
import org.apache.directory.server.kerberos.shared.store.operations.GetPrincipal;
import org.apache.directory.shared.ldap.name.LdapDN;


/**
 * A command object for exporting the Kerberos keys of a target principal.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class ExportKey
{
    /** The remote LDAP server name. */
    private String hostname;

    /** The remote LDAP server port. */
    private int port;

    /** The keytab file to write the keys to. */
    private String keytabFileName;

    /**
     * Sets system properties for help debugging.
     */
    static
    {
        System.setProperty( "javax.security.auth.useSubjectCredsOnly", "true" );
        System.setProperty( "sun.security.krb5.debug", "true" );
    }


    /**
     * Creates a new instance of ExportKey.
     *
     * @param hostname
     * @param port 
     */
    public ExportKey( String hostname, int port )
    {
        this.hostname = hostname;
        this.port = port;
    }


    /**
     * Execute the request to export keys to a keytab.  The search base DN is the root of the
     * sub-tree where principals can be found, eg "ou=users,dc=example,dc=com".
     * 
     * @param tgt 
     * @param serviceTicket 
     * @param searchBaseDn 
     * @param targetPrincipal 
     * @throws PasswordConnectionException 
     */
    public void execute( KerberosTicket tgt, KerberosTicket serviceTicket, String searchBaseDn,
        KerberosPrincipal targetPrincipal ) throws PasswordConnectionException
    {
        Subject subject = new Subject();
        subject.getPrivateCredentials().add( tgt );
        subject.getPrivateCredentials().add( serviceTicket );

        PrincipalStoreEntry entry = getContext( subject, searchBaseDn, targetPrincipal );

        Map<EncryptionType, EncryptionKey> map = entry.getKeyMap();

        writeKeytab( targetPrincipal.getName(), map );
    }


    /**
     * Perform JNDI work as authenticated Subject.
     *
     * @param subject
     */
    private PrincipalStoreEntry getContext( Subject subject, final String searchBaseDn,
        final KerberosPrincipal targetPrincipal ) throws PasswordConnectionException
    {
        Object entry;

        try
        {
            entry = Subject.doAs( subject, new PrivilegedExceptionAction()
            {
                public Object run() throws Exception
                {
                    try
                    {
                        // Create the initial context
                        Hashtable<String, String> env = new Hashtable<String, String>();
                        env.put( Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory" );
                        env.put( Context.PROVIDER_URL, "ldap://" + hostname + ":" + port + "/" + searchBaseDn );

                        // Request the use of the "GSSAPI" SASL mechanism
                        // Authenticate by using already established Kerberos credentials
                        env.put( Context.SECURITY_AUTHENTICATION, "GSSAPI" );

                        // Request privacy protection
                        env.put( "javax.security.sasl.qop", "auth-conf" );

                        // Request mutual authentication
                        env.put( "javax.security.sasl.server.authentication", "true" );

                        // Request high-strength cryptographic protection
                        env.put( "javax.security.sasl.strength", "high" );

                        env.put( "java.naming.ldap.attributes.binary", "krb5key" );

                        DirContext ctx = new InitialDirContext( env );

                        GetPrincipal getPrincipal = new GetPrincipal( targetPrincipal );

                        
                        return getPrincipal.execute( ctx, LdapDN.EMPTY_LDAPDN );
                    }
                    catch ( NamingException ne )
                    {
                        throw new PrivilegedActionException( ne );
                    }
                }
            } );
        }
        catch ( PrivilegedActionException pae )
        {
            throw new PasswordConnectionException( "Error retrieving principal.", pae.getCause() );
        }

        return ( PrincipalStoreEntry ) entry;
    }


    private void writeKeytab( String principalName, Map<EncryptionType, EncryptionKey> map )
        throws PasswordConnectionException
    {
        List<KeytabEntry> entries = new ArrayList<KeytabEntry>();

        Iterator<EncryptionKey> it = map.values().iterator();
        while ( it.hasNext() )
        {
            EncryptionKey key = it.next();
            entries.add( getEntry( principalName, key ) );
        }

        File file = new File( keytabFileName );
        Keytab keytab = new Keytab();
        keytab.setEntries( entries );

        try
        {
            keytab.write( file );
        }
        catch ( IOException ioe )
        {
            throw new PasswordConnectionException( "Error writing keytab.", ioe );
        }
    }


    /**
     * Returns a keytab entry for a principal name and encryption key.
     * 
     * TODO - Take principal type from entry when Kerberos schema support is available.
     * TODO - Take timestamp from entry when Kerberos schema support is available.
     * TODO - Take key version number from entry when Kerberos schema support is available.
     *
     * @param principalName
     * @param key
     * @return The keytab entry.
     */
    private KeytabEntry getEntry( String principalName, EncryptionKey key )
    {
        long principalType = 1;

        KerberosTime timeStamp = new KerberosTime();

        byte keyVersion = ( byte ) key.getKeyVersion();

        return new KeytabEntry( principalName, principalType, timeStamp, keyVersion, key );
    }
}
