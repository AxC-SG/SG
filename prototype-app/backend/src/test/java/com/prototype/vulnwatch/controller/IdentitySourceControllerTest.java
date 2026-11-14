package com.prototype.vulnwatch.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.service.RequestActor;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.ownership.IdentitySourceService;
import com.prototype.vulnwatch.service.ownership.IdentitySourceService.Preview;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;

class IdentitySourceControllerTest {

    @Test
    void previewResponsesAreNeverCached() {
        IdentitySourceService sources = mock(IdentitySourceService.class);
        RequestActorService actors = mock(RequestActorService.class);
        when(actors.currentActor()).thenReturn(new RequestActor("admin-1", false, UUID.randomUUID(), "Acme"));
        UUID id = UUID.randomUUID();
        Preview preview = new Preview(true, null, "Preview complete", List.of(), "token", null);
        when(sources.preview(id, "admin-1")).thenReturn(preview);

        var response = new IdentitySourceController(sources, actors).preview(id);

        assertThat(response.getHeaders().getCacheControl()).isEqualTo("no-store");
        assertThat(response.getHeaders().getFirst(HttpHeaders.PRAGMA)).isEqualTo("no-cache");
        assertThat(response.getBody()).isSameAs(preview);
    }
}
