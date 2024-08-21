# Goal:
Have an auth library that you can easily integrate into your go backend

- provide good code example with copy/pastable snippets instead of relying on overcomplicated adapters
- this allows for more customization

- create User and create a session

Requirements for session based:
## Session
- field: 
    - Key/Id
    - UserId
    - LastSeenTime
    - Expiry Date
    - LogInTime
    - Ip address? -> more location like country bcs of dynamic ip address
    - device?
- Lifetime: Default 30 days and reset if used within last 15days
- Sudo Mode -> For access-critical check when creds where used if to long reask
- Delete all session on new permissions or change of password
- Client Storage: 
    - HttpOnly: Cookies are only accessible server-side
    - SameSite=Lax: Use Strict for critical websites
    - Secure: Cookies can only be sent over HTTPS
    - Max-Age or Expires: Same as Session expiry date
    - Path=/: Cookies can be accessed from all routes

## Password Auth:
- 8 characters long
- maximums 127 chars
- [zxcvbn](https://github.com/dropbox/zxcvbn) for strength validation
- [haveibeenpwned](https://haveibeenpwned.com/API/v3) check for leakked passwords
- "golang.org/x/crypto/argon2"
- multifactor-authentication
- IP based throttling (10 min timeout after 10 failed attempts)
- Captchas (for bot protection)?
- Vague Error messaged (incorrect username or password) instead of individul error message
- ask for current password when user tries to change password 

## Email Verification -> external serice?
- block sub-addressing
- send OTP via email address -> people don't have to click on a link or links get sent to spam or change platform 
    - 8 digits or 6 alphanumeric (remove 0, O, 1, I, etc)
    - 15-30 mins validation 
    - immediatly invalid
- invalidate all session when an email is verified
- email change asked for password or 2fa
- new email stored separetely until its verified 
- email to old email
- rate limit on endpoints that send mails



