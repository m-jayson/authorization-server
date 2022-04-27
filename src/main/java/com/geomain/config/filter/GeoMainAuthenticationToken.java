package com.geomain.config.filter;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import java.util.Collection;

public class GeoMainAuthenticationToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = 560L;
    private final Object principal;
    private Object credentials;
    private String domain;

    public GeoMainAuthenticationToken(Object principal, Object credentials, String domain, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        this.domain = domain;
        super.setAuthenticated(true);
    }
    public GeoMainAuthenticationToken(Object principal, Object credentials, String domain) {
        super(null);
        this.principal = principal;
        this.credentials = credentials;
        this.domain = domain;
        this.setAuthenticated(false);
    }

    public Object getCredentials() {
        return this.credentials;
    }

    public Object getPrincipal() {
        return this.principal;
    }

    public String getDomain() {
        return domain;
    }

    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        Assert.isTrue(!isAuthenticated, "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        super.setAuthenticated(false);
    }

    public void eraseCredentials() {
        super.eraseCredentials();
        this.credentials = null;
    }
}