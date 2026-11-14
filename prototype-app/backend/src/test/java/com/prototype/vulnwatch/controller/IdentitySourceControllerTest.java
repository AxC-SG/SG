package com.prototype.vulnwatch.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.service.RequestActor;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.ownership.IdentitySourceService;
import com.prototype.vulnwatch.service.ownership.IdentitySourceService.Preview;
import com.prototype.vulnwatch.service.ownership.IdentitySourceService.SyncRequest;
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

    @Test
    void syncNowQueuesARunAndReturnsAcceptedWithAnIncrementalDefault() {
        IdentitySourceService sources = mock(IdentitySourceService.class);
        RequestActorService actors = mock(RequestActorService.class);
        when(actors.currentActor()).thenReturn(new RequestActor("admin-1", false, UUID.randomUUID(), "Acme"));
        UUID id = UUID.randomUUID();
        SyncRequest complete = new SyncRequest(UUID.randomUUID(), true);
        SyncRequest incremental = new SyncRequest(UUID.randomUUID(), false);
        when(sources.syncNow(id, true, "admin-1")).thenReturn(complete);
        when(sources.syncNow(id, false, "admin-1")).thenReturn(incremental);
        IdentitySourceController controller = new IdentitySourceController(sources, actors);

        var response = controller.sync(id, new IdentitySourceController.SyncNowRequest(true));
        assertThat(response.getStatusCode().value()).isEqualTo(202);
        assertThat(response.getBody()).isSameAs(complete);
        assertThat(controller.sync(id, null).getBody()).isSameAs(incremental);
    }
}
