/*
 *   Copyright 2004 The Apache Software Foundation
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */
package org.apache.kerberos.util;

import java.io.*;

import javax.security.auth.callback.*;

public class CallbackHandlerBean implements CallbackHandler {

	private String _name     = null;
	private String _password = null;

	public CallbackHandlerBean(String name, String password) {
		_name     = name;
		_password = password;
	}

	public void handle(Callback[] callbacks) throws UnsupportedCallbackException, IOException {
		for (int i = 0; i < callbacks.length; i++) {
			Callback callBack = callbacks[i];

			// Handles username callback.
			if (callBack instanceof NameCallback) {
				NameCallback nameCallback = (NameCallback) callBack;
				nameCallback.setName(_name);
			// Handles _password callback.
			} else if (callBack instanceof PasswordCallback) {
				PasswordCallback passwordCallback = (PasswordCallback) callBack;
				passwordCallback.setPassword(_password.toCharArray());
			} else {
				throw new UnsupportedCallbackException(callBack, "Callback not supported");
			}
		}
	}
}

