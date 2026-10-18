# Collecting Login Data from Social Media Platforms

Most platforms provide a way to see where you're logged in and sometimes a history of logins.

## Facebook
- Go to Settings & Privacy → Settings → Security and Login → Where You're Logged In.
- You can see active sessions but not a full history. To get history, you may need to download your information:
  - Settings → Your Facebook Information → Download Your Information.
  - Select "Login and Recovery" information.
- The exported JSON may contain login events.

## Instagram
- Similar to Facebook (owned by Meta).
- Settings → Security → Login Activity shows recent logins.
- Download your data via Settings → Privacy and Security → Download Data.

## Twitter/X
- Settings → Security and account access → Apps and sessions → Sessions.
- Shows active sessions; history may be limited.
- Request your archive via Settings → Account → Download an archive of your data.

## LinkedIn
- Settings → Sign in & security → Where you're signed in.
- Shows active sessions; you can download data via Settings → Data privacy → Get a copy of your data.

## TikTok
- Privacy and safety → Personalization and data → Download your data.
- Includes login history.

## Snapchat
- Settings → My Data → Submit Request.
- Includes login history.

## General Tips
- Look for files named like "login_history.json", "account_activity.json", or similar in the exported zip.
- The format varies; you may need to adapt the analyzer to match the structure.
- Ideally, each login event should have: timestamp, device type, location (IP or city), and status (login/logout or active/inactive).

If you cannot get a full history, you can still use the "Where you're logged in" list to see current sessions and note any unfamiliar ones.