package com.example.security.domain.member.member.controller;

import com.example.security.domain.member.member.dto.MemberDto;
import com.example.security.domain.member.member.entity.Member;
import com.example.security.domain.member.member.service.MemberService;
import com.example.security.global.Rq;
import com.example.security.global.dto.RsData;
import com.example.security.global.exception.ServiceException;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/members")
@RequiredArgsConstructor
public class ApiV1MemberController {

    private final MemberService memberService;
    private final Rq rq;

    record JoinReqBody(@NotBlank String username, @NotBlank String password, @NotBlank String nickname) {}

    @PostMapping("/join")
    public RsData<MemberDto> join(@RequestBody @Valid JoinReqBody reqBody) {

        memberService.findByUsername(reqBody.username())
                .ifPresent(_ -> {
                    throw new ServiceException("409-1", "이미 사용중인 아이디입니다.");
                });


        Member member = memberService.join(reqBody.username(), reqBody.password(), reqBody.nickname());
        return new RsData<>(
                "201-1",
                "회원 가입이 완료되었습니다.",
                new MemberDto(member)
                );
    }


    record LoginReqBody(@NotBlank String username, @NotBlank String password) {}

    record LoginResBody(MemberDto item, String apiKey) {}

    @PostMapping("/login")
    public RsData<LoginResBody> login(@RequestBody @Valid LoginReqBody reqBody) {

        Member member = memberService.findByUsername(reqBody.username()).orElseThrow(
                () -> new ServiceException("401-1", "잘못된 아이디입니다.")
        );

        if(!member.getPassword().equals(reqBody.password())) {
            throw new ServiceException("401-2", "비밀번호가 일치하지 않습니다.");
        }

        return new RsData<>(
                "200-1",
                "%s님 환영합니다.".formatted(member.getNickname()),
                new LoginResBody(
                        new MemberDto(member),
                        member.getApiKey()
                )
        );
    }

    @GetMapping("/me")
    public RsData<MemberDto> me() {

        Member actor = rq.getAuthenticatedActor();

        return new RsData<>(
                "200-1",
                "내 정보 조회가 완료되었습니다.",
                new MemberDto(actor)
        );
    }


}
