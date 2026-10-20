package com.prototype.vulnwatch.config;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.service.AppUserGlobalRoleService;
import com.prototype.vulnwatch.service.AuthTokenService;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtException;

class JwtModeContractTest {
    private static final String SECRET="0".repeat(32);
    @Test void localIssuedTokenMatchesDecoderAndRejectsWrongIssuerAudienceAndPurpose() throws Exception {
        AppUser user=new AppUser();user.setId(UUID.randomUUID());user.setExternalSubject("owner");user.setStatus("ACTIVE");user.setPlatformOwner(true);
        var roles=mock(AppUserGlobalRoleService.class);when(roles.rolesForUser(user.getId())).thenReturn(Set.of("PLATFORM_OWNER"));
        var issuer=new AuthTokenService(SECRET,5,"active_tenant_id",false,false,"",roles);
        String valid=issuer.issueToken(user,Set.of("PLATFORM_OWNER"),null).token();
        var decoder=new JwtDecoderConfig().jwtDecoder("","",SECRET,"scoutgrid-api","LOCAL","urn:scoutgrid:local");
        assertEquals("access",decoder.decode(valid).getClaimAsString("token_use"));
        var mapper=new com.fasterxml.jackson.databind.ObjectMapper();
        for (String field:java.util.List.of("iss","aud","token_use")) {
            var claims=mapper.readTree(java.util.Base64.getUrlDecoder().decode(valid.split("\\.")[1]));
            ((com.fasterxml.jackson.databind.node.ObjectNode)claims).put(field,"wrong");
            String prefix=valid.split("\\.")[0]+"."+java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(mapper.writeValueAsBytes(claims));
            var mac=javax.crypto.Mac.getInstance("HmacSHA256");mac.init(new javax.crypto.spec.SecretKeySpec(SECRET.getBytes(java.nio.charset.StandardCharsets.UTF_8),"HmacSHA256"));
            String invalid=prefix+"."+java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(prefix.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            assertThrows(JwtException.class,() -> decoder.decode(invalid),field);
        }
    }
    @Test void decoderRejectsAmbiguousModesBeforeExternalLookup() {
        var config=new JwtDecoderConfig();
        assertThrows(IllegalStateException.class,() -> config.jwtDecoder("https://issuer.test","",SECRET,"api","LOCAL","local"));
        assertThrows(IllegalStateException.class,() -> config.jwtDecoder("https://issuer.test","",SECRET,"api","EXTERNAL","local"));
        assertThrows(IllegalStateException.class,() -> config.jwtDecoder("","",SECRET,"api","TYPO","local"));
    }
}
