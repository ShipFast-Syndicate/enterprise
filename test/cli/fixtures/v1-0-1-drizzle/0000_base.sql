CREATE TABLE `user` (`id` text PRIMARY KEY NOT NULL, `name` text NOT NULL, `email` text NOT NULL, `emailVerified` integer NOT NULL, `createdAt` integer NOT NULL, `updatedAt` integer NOT NULL);
--> statement-breakpoint
CREATE TABLE `organization` (`id` text PRIMARY KEY NOT NULL, `name` text NOT NULL, `slug` text NOT NULL, `createdAt` integer NOT NULL);
