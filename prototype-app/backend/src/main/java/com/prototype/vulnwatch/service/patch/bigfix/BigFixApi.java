package com.prototype.vulnwatch.service.patch.bigfix;

import com.prototype.vulnwatch.client.http.BigFixHttpTransport;
import java.io.IOException;
import java.net.URI;
import java.util.List;
import org.apache.hc.core5.http.message.BasicNameValuePair;
import org.springframework.stereotype.Component;

/** The two BigFix REST calls the connector makes: sign-in check and session-relevance query. */
@Component
class BigFixApi {

    private final BigFixHttpTransport transport;

    BigFixApi(BigFixHttpTransport transport) {
        this.transport = transport;
    }

    void login(URI base, String username, String password) {
        BigFixHttpTransport.Response response = call(() -> transport.get(base, "/api/login", username, password));
        if (response.status() == 401 || response.status() == 403) {
            throw new IllegalStateException("BigFix rejected the operator credentials (HTTP " + response.status() + ")");
        }
        requireOk(response, "sign-in");
    }

    /**
     * Runs one of the connector's fixed relevance templates. The relevance is a compile-time
     * constant — tenant input never reaches it.
     */
    BigFixQueryParser.Rows query(URI base, String username, String password, String relevance, int maxRows) {
        BigFixHttpTransport.Response response = call(() -> transport.postForm(base, "/api/query",
                List.of(new BasicNameValuePair("relevance", relevance)), username, password));
        requireOk(response, "query");
        return BigFixQueryParser.parse(response.body(), maxRows);
    }

    private interface Call {
        BigFixHttpTransport.Response run() throws IOException;
    }

    private static BigFixHttpTransport.Response call(Call call) {
        try {
            return call.run();
        } catch (java.net.UnknownHostException rejected) {
            throw new IllegalStateException("BigFix server address was rejected or could not be resolved");
        } catch (javax.net.ssl.SSLException tls) {
            throw new IllegalStateException("TLS handshake with the BigFix server failed; its certificate must be trusted by the Scout backend");
        } catch (IOException failure) {
            throw new IllegalStateException("BigFix request failed: " + failure.getClass().getSimpleName());
        }
    }

    private static void requireOk(BigFixHttpTransport.Response response, String what) {
        if (response.status() < 200 || response.status() >= 300) {
            throw new IllegalStateException("BigFix " + what + " failed (HTTP " + response.status() + ")");
        }
    }
}
