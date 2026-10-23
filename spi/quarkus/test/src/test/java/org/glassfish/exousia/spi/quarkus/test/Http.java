/*
 * Copyright (c) 2026 Contributors to the Eclipse Foundation.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0, which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * This Source Code may also be made available under the following Secondary
 * Licenses when the conditions for such availability set forth in the
 * Eclipse Public License v. 2.0 are satisfied: GNU General Public License,
 * version 2 with the GNU Classpath Exception, which is available at
 * https://www.gnu.org/software/classpath/license.html.
 *
 * SPDX-License-Identifier: EPL-2.0 OR GPL-2.0 WITH Classpath-exception-2.0
 */
package org.glassfish.exousia.spi.quarkus.test;

import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.Base64;

final class Http {

    static HttpResponse<String> get(URL base, String path, String user, String password) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(base.toURI().resolve(path));
        if (user != null) {
            request.header("Authorization", "Basic " + Base64.getEncoder().encodeToString((user + ":" + password).getBytes()));
        }
        return HttpClient.newHttpClient().send(request.build(), BodyHandlers.ofString());
    }
}
