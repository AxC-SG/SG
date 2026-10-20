package com.prototype.vulnwatch.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record InvitationTokenRequest(@NotBlank @Size(max = 256) String token) { }
