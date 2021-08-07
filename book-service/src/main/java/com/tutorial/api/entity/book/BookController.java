package com.tutorial.api.entity.book;

import java.util.UUID;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/books")
public class BookController {

   @GetMapping("/{bookId}")
   @PreAuthorize("hasRole('USER')")
   public Book findById(@PathVariable String bookId) {
      Book book = new Book(bookId, UUID.randomUUID().toString(), "API Security", "UDemy", "07-29-2021");
      return book;
   }

   @PostMapping
   public Book save(@RequestBody Book book) {
      book.setBookId(UUID.randomUUID().toString());
      return book;
   }
}