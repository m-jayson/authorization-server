package com.geomain.config.provider;

import com.geomain.config.filter.GeoMainAuthenticationToken;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
public class GeoMainAuthenticationProvider implements AuthenticationProvider {

    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        var geoMainAuthenticationToken = (GeoMainAuthenticationToken) authentication;
        log.info("Sign in :: {},{},{}",geoMainAuthenticationToken.getDomain(),
                                       geoMainAuthenticationToken.getCredentials(),
                                       geoMainAuthenticationToken.getPrincipal());

//        throw new BadCredentialsException("Bad Credentials");
        return createSuccessAuthentication(geoMainAuthenticationToken,authentication);
    }

    private GeoMainAuthenticationToken createSuccessAuthentication(GeoMainAuthenticationToken geoMainAuthenticationToken,Authentication authentication) {
        Collection<? extends GrantedAuthority> authorities = this.authoritiesMapper.mapAuthorities(getGrantedAuthorities());
        var principal = "test"; //geoMainAuthenticationToken.getPrincipal();
        var credentials = "cred";// geoMainAuthenticationToken.getCredentials();
        var domain = "domain";//geoMainAuthenticationToken.getDomain();

        var result = new GeoMainAuthenticationToken(principal, credentials, domain, authorities);
        result.setDetails(authentication);

        log.info("Authenticated User");
        return result;
    }

    private Collection<? extends GrantedAuthority> getGrantedAuthorities() {
        return List.of(() -> "USER");
    }


    @Override
    public boolean supports(Class<?> authentication) {
        return GeoMainAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
