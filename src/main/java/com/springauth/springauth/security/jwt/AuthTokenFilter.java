package com.springauth.springauth.security.jwt;

import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AuthTokenFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
      try{
          String jwt = parseJwt(request);
          if(jwt !=null && jwtUtils)
      }
      catch(Exception e){
          logger.error("can not set user authentication: {}",e);
      }
      filterChain.doFilter(request,response);
    }

    private String parseJwt(HttpServletRequest request){
        String  headerAuth = request.getHeader("Authorisation");
        if(StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer")){
            return headerAuth.substring(7, headerAuth.length());
        }
        return null;
    }
}
