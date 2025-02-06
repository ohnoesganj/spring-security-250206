package com.example.security.domain.post.comment.controller;

import com.example.security.domain.member.member.entity.Member;
import com.example.security.domain.post.comment.dto.CommentDto;
import com.example.security.domain.post.comment.entity.Comment;
import com.example.security.domain.post.post.entity.Post;
import com.example.security.domain.post.post.service.PostService;
import com.example.security.global.Rq;
import com.example.security.global.dto.RsData;
import com.example.security.global.exception.ServiceException;
import lombok.RequiredArgsConstructor;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/posts/{postId}/comments")
public class ApiV1CommentController {

    private final PostService postService;
    private final Rq rq;

    @GetMapping
    @Transactional(readOnly = true)
    public List<CommentDto> getItems(@PathVariable long postId) {

        Post post = postService.getItem(postId).orElseThrow(
                () -> new ServiceException("404-1", "존재하지 않는 게시글입니다.")
        );

        return post.getComments()
                .stream()
                .map(CommentDto::new)
                .toList();
    }

    @GetMapping("{id}")
    @Transactional(readOnly = true)
    public CommentDto getItem(@PathVariable long postId, @PathVariable long id) {

        Post post = postService.getItem(postId).orElseThrow(
                () -> new ServiceException("404-1", "존재하지 않는 게시글입니다.")
        );

        Comment comment = post.getCommentById(id);

        return new CommentDto(comment);
    }


    record WriteReqBody(String content) {
    }

    @PostMapping
    @Transactional
    public RsData<Void> write(@PathVariable long postId, @RequestBody WriteReqBody reqBody) {
        Member actor = rq.getAuthenticatedActor();
        Comment comment = _write(postId, actor, reqBody.content());

        postService.flush();

        return new RsData<>(
                "201-1",
                "%d번 댓글 작성이 완료되었습니다.".formatted(comment.getId())
        );

    }


    record ModifyReqBody(String content) {}

    @PutMapping("{id}")
    @Transactional
    public RsData<Void> modify(@PathVariable long postId, @PathVariable long id, @RequestBody ModifyReqBody reqBody) {

        Member actor = rq.getAuthenticatedActor();

        Post post = postService.getItem(postId).orElseThrow(
                () -> new ServiceException("404-1", "존재하지 않는 게시글입니다.")
        );

        Comment comment = post.getCommentById(id);

        comment.canModify(actor);
        comment.modify(reqBody.content());

        return new RsData<>(
                "200-1",
                "%d번 댓글 수정이 완료되었습니다.".formatted(id)
        );
    }


    @DeleteMapping("{id}")
    @Transactional
    public RsData<Void> delete(@PathVariable long postId, @PathVariable long id) {

        Member actor = rq.getAuthenticatedActor();
        Post post = postService.getItem(postId).orElseThrow(
                () -> new ServiceException("404-1", "존재하지 않는 게시글입니다.")
        );

        Comment comment = post.getCommentById(id);

        comment.canDelete(actor);
        post.deleteComment(comment);

        return new RsData<>(
                "200-1",
                "%d번 댓글 삭제가 완료되었습니다.".formatted(id)
        );
    }


    public Comment _write(long postId, Member actor, String content) {

        Post post = postService.getItem(postId).orElseThrow(
                () -> new ServiceException("404-1", "존재하지 않는 게시글입니다.")
        );

        Comment comment = post.addComment(actor, content);

        return comment;
    }


}
