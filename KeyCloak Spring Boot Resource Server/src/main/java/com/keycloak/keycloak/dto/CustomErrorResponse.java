package com.keycloak.keycloak.dto;
public record CustomErrorResponse(int status, String error, String message) {}
