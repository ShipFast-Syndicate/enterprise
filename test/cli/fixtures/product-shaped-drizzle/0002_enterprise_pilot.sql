CREATE TABLE `org_policy` (`id` text, `org_id` text PRIMARY KEY NOT NULL, `require_2fa` integer DEFAULT 0 NOT NULL, `sso_enforced` integer DEFAULT 0 NOT NULL, `break_glass_user_id` text, `session_max_age_s` integer, `allowed_methods` text DEFAULT '["sso","magic_link","password"]' NOT NULL, `group_role_map` text DEFAULT '{}' NOT NULL, `updated_at` integer NOT NULL);
--> statement-breakpoint
CREATE UNIQUE INDEX `org_policy_id` ON `org_policy` (`id`);
