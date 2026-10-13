CREATE TABLE `enterprise_organization` (`id` text PRIMARY KEY NOT NULL, `name` text NOT NULL, `slug` text NOT NULL, `logo` text, `createdAt` integer NOT NULL, `metadata` text, `studio_ref` text);
--> statement-breakpoint
CREATE UNIQUE INDEX `enterprise_organization_slug_unique` ON `enterprise_organization` (`slug`);
--> statement-breakpoint
CREATE TABLE `enterprise_member` (`id` text PRIMARY KEY NOT NULL, `organizationId` text NOT NULL, `userId` text NOT NULL, `role` text DEFAULT 'member' NOT NULL, `createdAt` integer NOT NULL);
--> statement-breakpoint
CREATE TABLE `org_policy` (`id` text, `org_id` text PRIMARY KEY NOT NULL, `require_2fa` integer DEFAULT 0 NOT NULL, `sso_enforced` integer DEFAULT 0 NOT NULL, `break_glass_user_id` text, `session_max_age_s` integer, `allowed_methods` text DEFAULT '["sso","magic_link","google","github","linkedin","microsoft","password","passkey"]' NOT NULL, `group_role_map` text DEFAULT '{}' NOT NULL, `updated_at` integer NOT NULL);
--> statement-breakpoint
CREATE UNIQUE INDEX `org_policy_id` ON `org_policy` (`id`);
--> statement-breakpoint
CREATE TABLE `audit_event` (`id` text PRIMARY KEY NOT NULL, `org_id` text NOT NULL, `seq` integer NOT NULL, `actor_type` text NOT NULL, `actor_id` text, `action` text NOT NULL, `target_type` text NOT NULL, `target_id` text, `ip` text, `user_agent` text, `metadata` text NOT NULL, `created_at` integer NOT NULL, `prev_hash` text NOT NULL, `hash` text NOT NULL);
--> statement-breakpoint
CREATE TABLE `enterprise_scim_member` (`id` text PRIMARY KEY NOT NULL, `org_id` text NOT NULL, `user_id` text NOT NULL, `member_id` text NOT NULL, `last_role` text NOT NULL);
