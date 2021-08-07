/** USER **/
INSERT INTO `user` (`enabled`, `password`, `username`) VALUES (b'1', '{noop}myplaintextpassword', 'user1');
INSERT INTO `user` (`enabled`, `password`, `username`) VALUES (b'1', '{noop}myplaintextpassword', 'user2');

/** ROLE **/
INSERT INTO `role` (`code`) VALUES ('ROLE_ADMIN');
INSERT INTO `role` (`code`) VALUES ('ROLE_USER');

/** AUTHORITY **/
INSERT INTO `authority` (`code`, `description`, `role_id`) VALUES ('book:save', 'Add Book', 1);
INSERT INTO `authority` (`code`, `description`, `role_id`) VALUES ('book:view', 'View Book', 2);


/** USER ROLE LINK **/
INSERT INTO `user_role_link` (`user_id`, `role_id`) VALUES (1, 1);
INSERT INTO `user_role_link` (`user_id`, `role_id`) VALUES (1, 2);
INSERT INTO `user_role_link` (`user_id`, `role_id`) VALUES (2, 2);


