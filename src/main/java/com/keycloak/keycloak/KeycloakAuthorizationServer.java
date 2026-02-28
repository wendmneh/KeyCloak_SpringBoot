package com.keycloak.keycloak;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class KeycloakAuthorizationServer {

    public static void main(String[] args) {
        SpringApplication.run(KeycloakAuthorizationServer.class, args);
    }

}
