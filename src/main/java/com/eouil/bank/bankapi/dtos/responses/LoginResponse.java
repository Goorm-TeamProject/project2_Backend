package com.eouil.bank.bankapi.dtos.responses;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class LoginResponse {
    private final String refreshToken;
    private final boolean mfaRegistered;

}