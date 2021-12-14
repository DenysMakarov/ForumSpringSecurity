package telran.forumservice.service;

import org.springframework.stereotype.Service;
import telran.forumservice.dto.ContentDto;
import telran.forumservice.dto.DateCreatedDto;
import telran.forumservice.dto.MessageDto;
import telran.forumservice.dto.PostDto;
import telran.forumservice.model.Post;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

public interface ForumService {
    Post addPost(ContentDto contentDto, String author);
    PostDto findPostById(String id);
    PostDto removePost(String id);
    PostDto updatePost(String id, ContentDto contentDto);
    boolean addLikeToPost(String id);
    PostDto addCommentToPost(String id, String author, MessageDto message);
    List<PostDto> findPostsByAuthor(String author);
    List<PostDto> findPostsByTags(List<String> tags);
    List<PostDto> findPostsByDateCreated(DateCreatedDto date);

}
