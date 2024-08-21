# Tuersteher

This is an auth library that is inspired by [lucia-auth](https://lucia-auth.com/) 
and its developer [pilcrowonpaper](https://pilcrowonpaper.com/) and his [Copenhagen Book](https://thecopenhagenbook.com/)
where he talks about general guidelines to implementing auth in web applications. 
My decision on not to add database interactions is also based on his upcoming change to 
the [v4 changes to lucia-auth](https://github.com/lucia-auth/lucia/issues/1639) and I agree with his mentality 
therefore this library will provide the following:

A detailed guide on how to implement authentication (currently only session based) in Golang
that uses this library to add cookies based on the created session to the response and requests
and copy/pastable code examples of how to integrate these sessions with your database.

>Very important:
 this library does NOT interact in any way with any database, it is up to you to add this to the DB
 however there are [guides]() that will show you how you can ca

This library is supposed to be a mix of tutorial and library code, that is relatively simple.

## Supported WebServer:
Since the package is based on the net/http package from Go it should work with every web server 
library that uses the net/http package.
Examples are available for:

- [x] Echo
- [ ] Gin

## Supported Databases:
Every single one! This is totally up to you.
Examples are available for:

### Postgres:
- [x] sql
- [ ] sqlc
- [ ] Gorm

### MySql:
- [ ] sql
- [ ] sqlc
- [ ] Gorm

## Featueres/Tutorials to be added
- [ ] 2FA
- [ ] OAuth
- [ ] Email Verification
- [ ] Password reset
- [ ] Passkeys
