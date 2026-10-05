package net.java21.data2flow.auth.revocation.controller;

import jakarta.validation.Valid;
import net.java21.data2flow.auth.revocation.dto.BlacklistRequest;
import net.java21.data2flow.auth.revocation.dto.ReloadResponse;
import net.java21.data2flow.auth.revocation.service.RevocationService;
import net.java21.data2flow.contracts.web.ApiResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 내부 폐기 API. API-IAM-37b {@code POST /internal/auth/blacklists}(core → auth, 204, 멱등),
 * API-IAM-38 {@code POST /internal/auth/revocations/reload}(auth 자신·운영자).
 */
@RestController
@RequestMapping("/internal/auth")
public class InternalRevocationController {

    private final RevocationService revocations;

    public InternalRevocationController(RevocationService revocations) {
        this.revocations = revocations;
    }

    @PostMapping("/blacklists")
    public ResponseEntity<Void> blacklist(@Valid @RequestBody BlacklistRequest request) {
        revocations.revoke(request.sids(), request.jtis(), request.reason());
        revocations.revokeAccessTokens(request.tokenIds(), request.reason());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/revocations/reload")
    public ApiResponse<ReloadResponse> reload() {
        RevocationService.ReloadResult result = revocations.reload();
        return ApiResponse.success(new ReloadResponse(result.sids(), result.jtis()));
    }
}
