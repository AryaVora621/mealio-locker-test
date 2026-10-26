-- Mealio locker test: wireless lock/unlock for the ESP32 bench locker, kept in the live mealio
-- project under locker_test_* so it never touches the app's own lockers or reservations tables.
-- Shapes follow the app (a locker has a serial and locked/online state; codes are 5 keys (digits and A-D),
-- one use, expiring) so the device contract can move to the real tables later.
--
-- No table is readable or writable by anon/authenticated directly. Everything goes through the
-- security definer functions below, which check a key against locker_test_config. Key hashes are
-- inserted by hand and never committed:
--   insert into locker_test_config values ('device', '<sha256 hex>'), ('admin', '<sha256 hex>');

create table if not exists public.locker_test_config (
  name text primary key check (name in ('device', 'admin')),
  key_hash text not null
);

create table if not exists public.locker_test_devices (
  serial text primary key check (char_length(serial) between 1 and 40),
  locked boolean,
  last_seen timestamptz,
  command text check (command in ('lock', 'unlock')),
  command_at timestamptz,
  typed text,             -- what is on the keypad right now, for the site's live view
  typed_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.locker_test_codes (
  id uuid primary key default gen_random_uuid(),
  serial text not null references public.locker_test_devices(serial) on delete cascade,
  code text not null check (code ~ '^[0-9A-D]{5}$'),  -- digits and A-D, all keypad keys but * and #
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  used_at timestamptz
);
create index if not exists locker_test_codes_lookup on public.locker_test_codes (serial, code) where used_at is null;

create table if not exists public.locker_test_events (
  id bigserial primary key,
  serial text not null,
  kind text not null,
  detail text,
  created_at timestamptz not null default now()
);
create index if not exists locker_test_events_recent on public.locker_test_events (serial, created_at desc);

alter table public.locker_test_config enable row level security;
alter table public.locker_test_devices enable row level security;
alter table public.locker_test_codes enable row level security;
alter table public.locker_test_events enable row level security;
revoke all on public.locker_test_config, public.locker_test_devices, public.locker_test_codes, public.locker_test_events from anon, authenticated;

create or replace function public.locker_test_auth(p_name text, p_key text)
returns boolean language sql stable security definer set search_path = public, extensions as $$
  select exists (select 1 from locker_test_config
                  where name = p_name and key_hash = encode(digest(coalesce(p_key, ''), 'sha256'), 'hex'));
$$;
revoke execute on function public.locker_test_auth(text, text) from public, anon, authenticated;

-- Device check-in, about once a second: records it is online and whether it is locked, and hands
-- over a pending lock/unlock from the site (once; commands older than 30 s are dropped).
create or replace function public.locker_test_poll(p_key text, p_serial text, p_locked boolean, p_typed text default null)
returns text language plpgsql security definer set search_path = public as $$
declare
  v_cmd text;
  v_at timestamptz;
begin
  if not locker_test_auth('device', p_key) then raise exception 'unauthorized'; end if;
  insert into locker_test_devices (serial, locked, last_seen, typed, typed_at)
    values (p_serial, p_locked, now(), left(coalesce(p_typed, ''), 8), now())
    on conflict (serial) do update set locked = excluded.locked, last_seen = now(),
      typed = excluded.typed, typed_at = now()
    returning command, command_at into v_cmd, v_at;
  if v_cmd is not null then
    update locker_test_devices set command = null, command_at = null where serial = p_serial;
    if v_at < now() - interval '30 seconds' then return null; end if;
  end if;
  return v_cmd;
end $$;

-- Keypad entry: the device sends what was typed when # is pressed. A match is spent at once.
-- Returns the same {ok, granted, reason} shape as the app's device_submit_code, with its reasons
-- (malformed, rate_limited, expired, invalid), so the firmware can move to the real lock tables.
create or replace function public.locker_test_submit_code(p_key text, p_serial text, p_code text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  v_id uuid;
  v_reason text;
begin
  if not locker_test_auth('device', p_key) then raise exception 'unauthorized'; end if;
  if (select count(*) from locker_test_events where serial = p_serial and kind = 'code_rejected'
        and created_at > now() - interval '15 minutes') >= 5 then
    insert into locker_test_events (serial, kind) values (p_serial, 'keypad_rate_limited');
    return jsonb_build_object('ok', true, 'granted', false, 'reason', 'rate_limited', 'retry_after_minutes', 15);
  end if;
  if p_code is null or p_code !~ '^[0-9A-D]{5}$' then
    v_reason := 'malformed';
  else
    update locker_test_codes set used_at = now()
     where id = (select id from locker_test_codes
                  where serial = p_serial and code = p_code and used_at is null and expires_at > now()
                  order by created_at desc limit 1 for update skip locked)
     returning id into v_id;
    if v_id is null then
      v_reason := case when exists (select 1 from locker_test_codes where serial = p_serial and code = p_code
                                      and used_at is null and expires_at <= now()) then 'expired' else 'invalid' end;
    end if;
  end if;
  if v_id is not null then
    insert into locker_test_events (serial, kind, detail) values (p_serial, 'code_accepted', p_code);
    return jsonb_build_object('ok', true, 'granted', true);
  end if;
  -- wrong codes are logged by length only, so the log never holds a near-miss guess
  insert into locker_test_events (serial, kind, detail)
    values (p_serial, 'code_rejected', v_reason || ', ' || char_length(coalesce(p_code, '')) || ' keys');
  return jsonb_build_object('ok', true, 'granted', false, 'reason', v_reason);
end $$;

-- What the latch did, with the app's device_report_event names.
create or replace function public.locker_test_report_event(p_key text, p_serial text, p_event text)
returns jsonb language plpgsql security definer set search_path = public as $$
begin
  if not locker_test_auth('device', p_key) then raise exception 'unauthorized'; end if;
  if p_event not in ('unlocked', 'locked', 'unlock_failed', 'door_opened', 'door_closed', 'boot') then
    raise exception 'bad event';
  end if;
  insert into locker_test_events (serial, kind) values (p_serial, p_event);
  -- a latch move ends any entry in progress, so the stored keys go with it
  update locker_test_devices set typed = '', typed_at = now(),
    locked = case when p_event in ('unlocked', 'locked') then p_event = 'locked' else locked end,
    last_seen = now()
   where serial = p_serial;
  return jsonb_build_object('ok', true);
end $$;

-- Admin check for the site's functions. Wrong passwords are logged and, after 20 in 15 minutes,
-- every admin call is refused (the right password too) until the window passes, so the public
-- endpoint cannot be used to guess the password. The callers return {error} instead of raising,
-- because raising would roll back the logged failure.
create or replace function public.locker_test_admin_ok(p_key text)
returns boolean language plpgsql security definer set search_path = public as $$
begin
  if (select count(*) from locker_test_events where serial = '-' and kind = 'admin_auth_failed'
        and created_at > now() - interval '15 minutes') >= 20 then
    return false;
  end if;
  if locker_test_auth('admin', p_key) then return true; end if;
  insert into locker_test_events (serial, kind) values ('-', 'admin_auth_failed');
  return false;
end $$;
revoke execute on function public.locker_test_admin_ok(text) from public, anon, authenticated;

create or replace function public.locker_test_new_code(p_key text, p_serial text, p_minutes int)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare
  v_alphabet constant text := '0123456789ABCD';
  v_code text := '';
  v_byte int;
  v_row locker_test_codes;
begin
  if not locker_test_admin_ok(p_key) then return json_build_object('error', 'unauthorized'); end if;
  insert into locker_test_devices (serial) values (p_serial) on conflict do nothing;
  -- 5 keys from the 14 the keypad can type (# submits, * clears); bytes of 252 and up are
  -- redrawn so every key is equally likely
  while char_length(v_code) < 5 loop
    v_byte := get_byte(gen_random_bytes(1), 0);
    if v_byte < 252 then v_code := v_code || substr(v_alphabet, v_byte % 14 + 1, 1); end if;
  end loop;
  insert into locker_test_codes (serial, code, expires_at)
    values (p_serial, v_code, now() + make_interval(mins => least(greatest(coalesce(p_minutes, 15), 1), 1440)))
    returning * into v_row;
  insert into locker_test_events (serial, kind) values (p_serial, 'code_created');
  return json_build_object('id', v_row.id, 'code', v_row.code, 'expires_at', v_row.expires_at);
end $$;

create or replace function public.locker_test_command(p_key text, p_serial text, p_command text)
returns json language plpgsql security definer set search_path = public as $$
begin
  if not locker_test_admin_ok(p_key) then return json_build_object('error', 'unauthorized'); end if;
  if p_command not in ('lock', 'unlock') then raise exception 'bad command'; end if;
  insert into locker_test_devices (serial) values (p_serial) on conflict do nothing;
  update locker_test_devices set command = p_command, command_at = now() where serial = p_serial;
  insert into locker_test_events (serial, kind) values (p_serial, 'command_' || p_command);
  return json_build_object('ok', true);
end $$;

create or replace function public.locker_test_state(p_key text, p_serial text)
returns json language plpgsql security definer set search_path = public as $$
begin
  if not locker_test_admin_ok(p_key) then return json_build_object('error', 'unauthorized'); end if;
  return json_build_object(
    'device', (select json_build_object('serial', serial, 'locked', locked, 'last_seen', last_seen,
                                        'online', last_seen > now() - interval '10 seconds', 'command', command,
                                        'typed', case when typed_at > now() - interval '10 seconds' then coalesce(typed, '') else '' end)
                 from locker_test_devices where serial = p_serial),
    'codes', coalesce((select json_agg(c order by c.created_at desc) from (
                select code, created_at, expires_at, used_at from locker_test_codes
                 where serial = p_serial order by created_at desc limit 8) c), '[]'::json),
    'events', coalesce((select json_agg(e order by e.created_at desc) from (
                select kind, detail, created_at from locker_test_events
                 where serial = p_serial order by created_at desc limit 20) e), '[]'::json),
    'now', now());
end $$;

revoke execute on function public.locker_test_poll(text, text, boolean, text), public.locker_test_submit_code(text, text, text), public.locker_test_report_event(text, text, text),
  public.locker_test_new_code(text, text, int), public.locker_test_command(text, text, text),
  public.locker_test_state(text, text) from public;
grant execute on function public.locker_test_poll(text, text, boolean, text), public.locker_test_submit_code(text, text, text), public.locker_test_report_event(text, text, text),
  public.locker_test_new_code(text, text, int), public.locker_test_command(text, text, text),
  public.locker_test_state(text, text) to anon, authenticated;
