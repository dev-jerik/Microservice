package com.tutorial.api.entity.book;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class Book {
   private String bookId;
   private String isbn;
   private String title;
   private String publisher;
   private String datePublished;
}
