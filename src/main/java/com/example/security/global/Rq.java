package com.example.security.global;

import com.example.security.domain.member.member.entity.Member;
import com.example.security.domain.member.member.service.MemberService;
import com.example.security.global.exception.ServiceException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.RequestScope;

import java.util.Optional;

// Request, Response, Session, Cookie, Header
@Component
@RequiredArgsConstructor
@RequestScope
public class Rq {

    private final HttpServletRequest request;
    private final MemberService memberService;

    public Member getAuthenticatedActor() {

        String authorizationValue = request.getHeader("Authorization");
        String apiKey = authorizationValue.substring("Bearer ".length());
        Optional<Member> opActor = memberService.findByApiKey(apiKey);

        if(opActor.isEmpty()) {
            throw new ServiceException("401-1", "잘못된 인증키입니다.");
        }

        return opActor.get();

    }
}
