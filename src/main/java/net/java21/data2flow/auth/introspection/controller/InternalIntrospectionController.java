package net.java21.data2flow.auth.introspection.controller;

import net.java21.data2flow.auth.introspection.dto.IntrospectionResponse;
import net.java21.data2flow.auth.introspection.service.IntrospectionService;
import net.java21.data2flow.contracts.web.ApiResponse;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** API-IAM-34 {@code POST /internal/auth/introspect} (form {@code token=…}). 호출: gateway만(ADR-021, 내부망) */
@RestController
@RequestMapping("/internal/auth")
public class InternalIntrospectionController {

    private final IntrospectionService introspection;

    public InternalIntrospectionController(IntrospectionService introspection) {
        this.introspection = introspection;
    }

    @PostMapping(path = "/introspect", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ApiResponse<IntrospectionResponse> introspect(@RequestParam(name = "token", required = false) String token) {
        return ApiResponse.success(introspection.introspect(token));
    }
}
