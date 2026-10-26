# Mealio locker test

A one-page site for testing the Mealio bench locker over WiFi: make a pickup code, type it on the
locker's keypad, and watch it open. The site can also lock and unlock the locker directly.

The locker is an ESP32 with a 4x4 keypad and a servo latch. Its firmware lives in the Mealio repo
(`hardware/firmware`, build `cloud`). It joins a phone hotspot and talks to this site's Supabase
functions over HTTPS.

## How it fits together

```
phone / laptop  ──>  index.html  ──>  Supabase RPC (locker_test_*)  <──  ESP32 locker on a hotspot
```

- `index.html` is the whole site: static, no build step. It calls the database functions with the
  admin password.
- `supabase/schema.sql` holds the tables and functions. They live in the Mealio Supabase project
  under `locker_test_*`, separate from the app's real lock tables.
- Every function checks a key in the database: the admin password for the site, a device key for
  the locker. The tables themselves can't be read or written with the public key. Only the key
  hashes are stored, and they are not in this repo.

## The locker's side

The locker calls the same three things the Mealio app's real device API has, so moving to the
app's `smart_locks` later only means changing the endpoint:

| Locker calls | When | Mirrors the app's |
| --- | --- | --- |
| `locker_test_poll(key, serial, locked)` | About once a second; returns `"unlock"`, `"lock"` or `null` | lock check-in |
| `locker_test_submit_code(key, serial, code)` | When # is pressed; returns `{ok, granted, reason}` | `device_submit_code` |
| `locker_test_report_event(key, serial, event)` | After the latch moves: `unlocked`, `locked`, `boot` | `device_report_event` |

Codes are 5 digits, single use, and expire after 15 minutes, like the app's pickup codes. Five
wrong codes in 15 minutes pause the keypad.

## Running it

Open `index.html` in a browser, or use the deployed site, and sign in with the admin password.
The password is kept in `.admin-password`, which is gitignored and only on the machine that set
it up.

The ESP32 only sees 2.4 GHz WiFi. On iPhone, turn on Settings > Personal Hotspot > Maximize
Compatibility. On Android, set the hotspot band to 2.4 GHz.
