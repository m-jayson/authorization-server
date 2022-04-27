package com.geomain;

import com.geomain.domain.UserAccount;
import com.geomain.repository.UserAccountRepository;
import java.util.UUID;
import javax.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.transaction.annotation.Transactional;

@SpringBootApplication
public class Main {

    public static void main(String[] args) {
        SpringApplication.run(Main.class, args);
    }

    @Autowired
    private UserAccountRepository userAccountRepository;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Transactional
    @PostConstruct
    public void setupTestData() {
        UserAccount account = new UserAccount.Builder()
                .withUsername("username")
                .withPassword(new BCryptPasswordEncoder().encode("password"))
                .build();

        userAccountRepository.save(account);

        RegisteredClient registrationClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("registration-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("client.create")
                .build();

        registeredClientRepository.save(registrationClient);

        ClientSettings clientSettings = ClientSettings.builder()
                .requireAuthorizationConsent(true)
                .requireProofKey(false)
                .build();

        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientSettings(clientSettings)
                .clientId("articles-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://127.0.0.1:4200")
                .redirectUri("http://127.0.0.1:4200/")
                .redirectUri("http://127.0.0.1:4200/silent-renew.html")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .requireProofKey(true)
                        .build())
                .scope(OidcScopes.OPENID)
                .scope("offline_access")
                .build();

        registeredClientRepository.save(registeredClient);

    }
}
