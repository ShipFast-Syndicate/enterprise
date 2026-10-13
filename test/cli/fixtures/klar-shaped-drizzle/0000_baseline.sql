CREATE TABLE `user` (`id` text PRIMARY KEY NOT NULL, `name` text NOT NULL, `email` text NOT NULL, `emailVerified` integer NOT NULL, `image` text, `createdAt` integer NOT NULL, `updatedAt` integer NOT NULL, `role` text, `banned` integer, `banReason` text, `banExpires` integer, `twoFactorEnabled` integer);
--> statement-breakpoint
CREATE UNIQUE INDEX `user_email_unique` ON `user` (`email`);
--> statement-breakpoint
CREATE TABLE `session` (`id` text PRIMARY KEY NOT NULL, `expires_at` integer NOT NULL, `token` text NOT NULL, `created_at` integer NOT NULL, `updated_at` integer NOT NULL, `ip_address` text, `user_agent` text, `activeOrganizationId` text, `activeTeamId` text, `impersonatedBy` text, `user_id` text NOT NULL);
--> statement-breakpoint
CREATE TABLE `account` (`id` text PRIMARY KEY NOT NULL, `accountId` text NOT NULL, `providerId` text NOT NULL, `userId` text NOT NULL, `password` text, `createdAt` integer NOT NULL, `updatedAt` integer NOT NULL);
--> statement-breakpoint
CREATE TABLE `verification` (`id` text PRIMARY KEY NOT NULL, `identifier` text NOT NULL, `value` text NOT NULL, `expiresAt` integer NOT NULL, `createdAt` integer, `updatedAt` integer);
