package com.prototype.vulnwatch.client.http;

import java.net.InetAddress;
import java.util.function.Function;

/** Test access to {@link BigFixHostPolicy} with a fixed resolver. */
public final class BigFixTestPolicies {

    private BigFixTestPolicies() { }

    public static BigFixHostPolicy withResolver(String allowedHosts, Function<String, InetAddress[]> resolver) {
        return new BigFixHostPolicy(allowedHosts, resolver);
    }
}
