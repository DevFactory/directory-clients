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
package org.apache.directory.client.realm;


import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.security.PrivilegedAction;
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
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.directory.server.kerberos.shared.crypto.encryption.EncryptionType;
import org.apache.directory.server.kerberos.shared.jaas.CallbackHandlerBean;
import org.apache.directory.server.kerberos.shared.jaas.Krb5LoginConfiguration;
import org.apache.directory.server.kerberos.shared.keytab.Keytab;
import org.apache.directory.server.kerberos.shared.keytab.KeytabEntry;
import org.apache.directory.server.kerberos.shared.messages.value.EncryptionKey;
import org.apache.directory.server.kerberos.shared.messages.value.KerberosTime;
import org.apache.directory.server.kerberos.shared.store.PrincipalStoreEntry;
import org.apache.directory.server.kerberos.shared.store.operations.GetPrincipal;


/**
 * A command-line client for exporting Kerberos symmetric keys.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class ExportKey
{
    private String hostname = "ldap.example.com";
    private String realm = "EXAMPLE.COM";
    private int port = 389;
    private String principalName = "ldap/" + hostname + "@" + realm;
    private String kdc = "localhost";
    private String username = "hnelson";
    private String password = "s3crEt";
    private String keytabFileName = "/root/test.keytab";

    private DirContext ctx;

    static BufferedReader in;


    /**
     * Creates a new instance of ExportKey and sets JAAS system properties
     * for the KDC and realm, so we don't have to rely on external configuration.
     */
    public ExportKey()
    {
        System.setProperty( "java.security.krb5.realm", realm );
        System.setProperty( "java.security.krb5.kdc", kdc );
    }


    /**
     * TODO - Add CLI support for parameters:
     * client name
     * baseDN
     * server
     * service
     * filename
     *
     * @param args
     * @throws Exception
     */
    public static void main( String[] args ) throws Exception
    {
        new ExportKey().go();
    }


    /*
     in = new BufferedReader( new InputStreamReader( System.in ) );
     String name = getInputString( "What is your name? " );
     System.out.println( "Your name is " + name );
     */
    private static String getInputString( String prompt ) throws IOException
    {
        System.out.print( prompt );
        return in.readLine();
    }


    /**
     * Setup context as remote.
     * Call GetPrincipal.
     * Use PrincipalEntry and reconstituteKeyMap().
     */
    public void go()
    {
        Subject subject = getSubject();

        getContext( subject );
    }


    /**
     * Gets the {@link Subject}.
     */
    private Subject getSubject()
    {
        // Use our custom configuration to avoid reliance on external config
        Configuration.setConfiguration( new Krb5LoginConfiguration() );

        // 1. Authenticate to Kerberos.
        LoginContext lc = null;
        try
        {
            lc = new LoginContext( ExportKey.class.getName(), new CallbackHandlerBean( username, password ) );
            lc.login();
        }
        catch ( LoginException le )
        {
            // Bad username:  Client not found in Kerberos database
            // Bad password:  Integrity check on decrypted field failed
            System.out.println( "Authentication failed:  " + le.getMessage() );
        }

        return lc.getSubject();
    }


    private void getContext( Subject subject )
    {
        // 2. Perform JNDI work as authenticated Subject.
        Subject.doAs( subject, new PrivilegedAction()
        {
            public Object run()
            {
                try
                {
                    // Create the initial context
                    Hashtable<String, String> env = new Hashtable<String, String>();
                    env.put( Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory" );
                    env.put( Context.PROVIDER_URL, "ldap://" + hostname + ":" + port + "/ou=users,dc=example,dc=com" );

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

                    ctx = new InitialDirContext( env );

                    KerberosPrincipal principal = new KerberosPrincipal( principalName );
                    GetPrincipal getPrincipal = new GetPrincipal( principal );

                    PrincipalStoreEntry entry = ( PrincipalStoreEntry ) getPrincipal.execute( ctx, null );

                    Map<EncryptionType, EncryptionKey> map = entry.getKeyMap();

                    writeKeytab( map );
                }
                catch ( NamingException e )
                {
                    e.printStackTrace();
                    System.out.println( "Should not have caught exception:  " + e.getMessage() );
                }
                catch ( IOException ioe )
                {
                    ioe.printStackTrace();
                    System.out.println( "Should not have caught exception:  " + ioe.getMessage() );
                }

                return null;
            }
        } );
    }


    private void writeKeytab( Map<EncryptionType, EncryptionKey> map ) throws IOException
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
        keytab.write( file );
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
