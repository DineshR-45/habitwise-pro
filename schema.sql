-- ═══════════════════════════════════════════════════
-- HabitWise Pro — Supabase Database Schema
-- Run this in your Supabase SQL Editor
-- ═══════════════════════════════════════════════════

-- USERS TABLE
create table if not exists users (
  id uuid default gen_random_uuid() primary key,
  name text not null,
  email text unique not null,
  password_hash text not null,
  created_at timestamptz default now()
);

-- OTP CODES TABLE (for password reset)
create table if not exists otp_codes (
  id uuid default gen_random_uuid() primary key,
  user_id uuid references users(id) on delete cascade,
  email text unique not null,
  otp_hash text not null,
  expires_at timestamptz not null,
  used boolean default false,
  created_at timestamptz default now()
);

-- HABITS TABLE
create table if not exists habits (
  id uuid default gen_random_uuid() primary key,
  user_id uuid references users(id) on delete cascade,
  habit_id text,
  name text not null,
  emoji text default '🎯',
  color jsonb default '{}',
  category text default 'daily',
  completions jsonb default '{}',
  note text default '',
  created_on text,
  goal_num integer default 0,
  goal_unit text default '',
  goal_progress jsonb default '{}',
  created_at timestamptz default now()
);

-- USER SETTINGS TABLE
create table if not exists user_settings (
  id uuid default gen_random_uuid() primary key,
  user_id uuid unique references users(id) on delete cascade,
  dark_mode boolean default false,
  reminder_dismissed text default '',
  updated_at timestamptz default now()
);

-- ROW LEVEL SECURITY (disable for service key access)
alter table users enable row level security;
alter table otp_codes enable row level security;
alter table habits enable row level security;
alter table user_settings enable row level security;

-- Allow service role full access (our backend uses service key)
create policy "Service role full access - users" on users for all using (true);
create policy "Service role full access - otp" on otp_codes for all using (true);
create policy "Service role full access - habits" on habits for all using (true);
create policy "Service role full access - settings" on user_settings for all using (true);
