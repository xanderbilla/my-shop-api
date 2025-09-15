package com.shop.auth.config;

import com.shop.auth.filter.CookieAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class FilterConfig {

    private final CookieAuthenticationFilter cookieAuthenticationFilter;

    @Bean
    public FilterRegistrationBean<CookieAuthenticationFilter> cookieAuthFilter() {
        FilterRegistrationBean<CookieAuthenticationFilter> registrationBean = new FilterRegistrationBean<>();
        
        registrationBean.setFilter(cookieAuthenticationFilter);
        registrationBean.addUrlPatterns("/api/v1/auth/*");
        registrationBean.setOrder(1); // Set filter order
        registrationBean.setName("cookieAuthenticationFilter");
        
        return registrationBean;
    }
}