# Pre-deploy checklist

A clean SiegeKit run means the automated checks that ran found nothing. It does **not** mean your application is secure. Automated tools catch known patterns; the items below need a person. Work through them before deploying, especially for code that was generated or written quickly.

For a complete, structured list of requirements, see the [OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard/).

## 1. Check the SiegeKit report itself

- [ ] Every test family you need ran; none were skipped, failed or timed out.
- [ ] Web/API tests were run **logged in**, for each user role, not only as an anonymous visitor.
- [ ] The number of pages/endpoints reached matches what your app actually has.
- [ ] All critical and high findings are fixed or consciously accepted with a written reason.

## 2. Access control (most common serious flaw scanners miss)

- [ ] Every request that reads or changes data checks that **this** user may access **this** record, on the server.
- [ ] Changing an ID in a URL or request body cannot reveal or modify another user's data.
- [ ] Admin functions are unreachable for normal users, not just hidden in the UI.

## 3. Authentication and sessions

- [ ] Passwords are hashed with a slow, salted algorithm (for example Argon2id or bcrypt), never stored or logged in plain text.
- [ ] Login, signup and password reset are rate-limited.
- [ ] Sessions expire, are invalidated on logout and password change, and cookies are `Secure` and `HttpOnly`.

## 4. Business logic

- [ ] Multi-step flows (checkout, signup, approvals) cannot be skipped or replayed.
- [ ] Prices, quantities, roles and limits are decided by the server, not trusted from the client.

## 5. Secrets and configuration

- [ ] No secrets in the repository or its history (SiegeKit checks this) and none in client-side code or container images.
- [ ] Production uses different credentials from development, each with the least privilege it needs.
- [ ] Debug modes, sample accounts and default passwords are off.

## 6. Data and infrastructure

- [ ] Database and storage are not reachable from the internet unless required.
- [ ] Backups exist and a restore has been tested.
- [ ] TLS is enforced for all traffic.
- [ ] Cloud and hosting settings (buckets, firewall rules, IAM) are reviewed; SiegeKit does not audit cloud accounts.

## 7. Monitoring and response

- [ ] Security-relevant events (logins, permission changes, errors) are logged without logging secrets.
- [ ] Someone is alerted when something goes wrong, and you know how you would roll back.

## 8. When to get a human review

- [ ] If the app handles payments, health data, personal data at scale, or anything you could be sued over, have an experienced person review the code or run a manual penetration test before launch.
