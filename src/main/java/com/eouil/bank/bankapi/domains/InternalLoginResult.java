package com.eouil.bank.bankapi.domains;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class InternalLoginResult {
    private final String accessToken;
    private final String refreshToken;
    private final boolean mfaRegistered;
}