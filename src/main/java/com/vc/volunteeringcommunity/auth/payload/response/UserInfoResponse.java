package com.vc.volunteeringcommunity.auth.payload.response;

import javax.validation.constraints.NotBlank;

public class UserInfoResponse {
    @NotBlank
    private final String displayName;

    public UserInfoResponse(@NotBlank String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}

