# R4 browser session — 2026-10-06, 15:35:27–15:45:48 and 16:09:36–16:11:38

Source: screen recording `Masterarbeit/Bildschirmaufnahme 2026-10-06 um 15.35.27.mov`
(10 min 32 s, 4096×2502, 38.7 fps; not committed, 684 MB). Times = recording start
(15:35:27, from the file name) + video offset; they agree with the on-screen menu-bar clock.
Analysis: frames extracted at screen changes (0.5 s sampling), read frame by frame; the
supplier side ran in the right-hand (Guest) window, the operator side in the left window.
Counting rule (Ch. 4): one interaction = one page on which the user must act, or one
wallet/key dialog the user must complete, from opening the invitation to the first
signed (A) / submitted (B) contribution. Opening the mailbox counts as one interaction
(e-mail). Pure waits are listed in brackets and not counted.

Origins: Design B `app.trustdpp.co` (trustMode design-b), Design A `web3.trustdpp.co`
(trustMode design-a). Supplier mailbox: `wicosi1774@hudzer.com` (temp-mail), used for
BOTH designs. Operator B: "Musclor AI"; operator A: "Zyton GmbH" (Google sign-in).
Products: B "T-Shirt" `dpp_806e2c79e92bb84e`; A "Zyton Heavyweight Organic Tee"
`dpp_38e8491ab51db46c`. Stage invited on both: Fabric Formation.

## Flow 3 — Supplier, Design B (start 15:36:36, end 15:37:57, 81 s)
| # | time | type | screen | action |
|---|---|---|---|---|
| 1 | 15:36:36 | e-mail | invitation e-mail "Musclor AI invited you" | opened, clicked "Accept invitation" (15:36:38) |
| 2 | 15:36:39 | page | "Accept & set your password" (name, company, password) | filled the three fields, pressed "Accept invitation" (≈15:37:08) |
| – | 15:37:03–07 | (browser) | detour into Chrome's own password manager | not the application; not counted |
| 3 | 15:37:13 | page | "Your assignments" | opened the T-Shirt assignment (15:37:24) |
| 4 | 15:37:31 | page | contribution form, 4 empty fields | filled Knitted / Circular knitting / 233 / Construction Detail, pressed "Submit for review" |
| – | 15:37:57 | (end) | "Your contribution: Submitted" | |
**Count: 4 interactions (1 e-mail, 3 pages, 0 wallet dialogs). No signature by the supplier.**

## Flow 4 — Operator, Design B (approval 15:38:10–15:38:24.5; NO publish recorded)
| # | time | type | action |
|---|---|---|---|
| 1 | 15:38:10 | page | opened the submitted node ("Submitted for your review") |
| 2 | 15:38:12 | page | pressed "Approve"; toast "Contribution approved / Node saved" at 15:38:24.5 |
| – | 15:38:28, 15:38:56 | (not publish) | clicked the "open public page" icon next to "Publish Changes" (checked at full resolution); browsed the EARLIER published passport until 15:39:11 |
| – | 15:39:12–16 | (state) | editor again; "Publish Changes" still lit (unpublished changes); left for web3.trustdpp.co |
**Count (approval only): 2 pages, 0 wallet dialogs, ≈ 14 s. Design B publish was not performed in the recorded session.**

Design B publish, added 2026-10-06 after the session: performed and timed by the author with a stopwatch,
NOT screen-recorded — ≈ 8 s. Interactions from the shipped code (`ProducerDashboard.tsx` → `PublishConfirmModal`
in `components/producer/modals.tsx`): "Publish Changes" → dialog "Publish this passport?" (Cancel / Publish, no
checkbox, no key dialog) → toast "DPP published — live" = 2 pages.
**Operator totals: Design A 8 (approval 3, publish 4, "Done" 1); Design B 4 (approval 2, publish 2).**
Comparable Design A approval: 3 interactions (open, approve dialog, Google sign-in), ≈ 26 s (15:45:20 → 15:45:46).

## Flow 1 — Supplier, Design A (start 15:41:10, end 15:45:11, 241 s)
| # | time | type | screen | action |
|---|---|---|---|---|
| – | 15:40:55 | (error) | old Design B invitation opened by mistake (same mailbox) | not counted |
| 1 | 15:41:10 | e-mail | invitation e-mail "Zyton GmbH invited you" | opened, clicked "Accept invitation" (15:41:13) |
| 2 | 15:41:14 | page | "Accept your invitation" | typed company "Fabric Formation", pressed "Create your account" |
| 3 | 15:41:29 | wallet | key-infrastructure sign-in ("Anmelden") | chose "Continue with e-mail" (address pre-filled, nothing typed) |
| 4 | 15:41:43 | wallet | e-mail verification, 6-digit code | entered code 378577 (15:42:12) |
| 5 | 15:42:1x | e-mail | mailbox | read the login code |
| 6 | 15:42:22 | wallet | "Set up multi-factor authentication" | pressed "Activate MFA" |
| 7 | 15:42:26 | wallet | "Add an authentication method" (authenticator app marked required) | chose authenticator app |
| 8 | 15:42:30 | wallet | "Set up authenticator app" + QR code | scanned with the phone (off screen), pressed "Next" |
| 9 | 15:42:43 | wallet | "Check your authenticator app", 6-digit code | entered the app's code |
| 10 | 15:42:57 | wallet | "Set up additional methods" | pressed "Finish" |
| 11 | 15:43:00 | wallet | "Add a passkey" | pressed "Set up later" |
| 12 | 15:43:04 | wallet | "Your recovery factor is set up" | pressed "Done" |
| – | 15:43:07–10 | (wait) | "Confirm your e-mail", "We sent a request to your wallet", tick | |
| 13 | 15:43:11 | page | "Your assignments" | opened the product (15:43:19); a sign-in dialog was visible 15:43:11–15:43:19 and closed without input (see findings) |
| – | 15:43:39 | (browser) | Chrome "search for devices on the local network?" prompt | not the application; not counted |
| 14 | 15:43:25 | page | contribution page, fields PREFILLED ("Needs re-confirming, signed 19.8.2026") | pressed "Review and re-confirm" (15:44:01) |
| 15 | 15:44:03 | page | "You are about to confirm — Your Fabric Formation credential" (signing as did:ethr:0x13882:0xfb50…2bac) | ticked the statement box, pressed "Confirm and submit" (15:44:08) |
| 16 | 15:44:13 | wallet | sign-in dialog again | chose "Continue with e-mail" |
| 17 | 15:44:20 | wallet | e-mail verification, 6-digit code | typed 887722 → "Invalid OTP" (15:44:46); re-entered 134456 (15:45:02) |
| 18 | 15:44:53 | e-mail | mailbox | read the second login code |
| – | 15:45:07 | (wait) | "Reconstructing your key…" | |
| – | 15:45:11 | (end) | "Confirmed and sent for review", signed 6.10.2026 15:45:11 | |
**Count: 18 interactions (3 e-mail, 4 pages, 11 wallet dialogs), plus one off-screen
phone action (QR scan + reading the authenticator code). Of these, 10 are one-time
account setup (#3–#12) and 4 belong to the signing ceremony (#15–#18).**
Signing ceremony: "Confirm and submit" 15:44:08 → signed 15:45:11 = 63 s, of which the
re-login with one invalid code took most; key reconstruction to confirmation ≈ 4 s
(15:45:07 → 15:45:11).

## Flow 2 — Operator, Design A (approval 15:45:20–15:45:46; publish 16:09:36–16:11:28)
Approval from the first recording; publish from the second recording
`Masterarbeit/Bildschirmaufnahme 2026-10-06 um 16.09.36.mov` (2 min 2 s, start 16:09:36 from the file name).
| # | time | type | action |
|---|---|---|---|
| 1 | 15:45:20 | page | opened the submitted node ("Submitted for your review") |
| 2 | 15:45:27 | page | "Approve this supplier's contribution": ticked the box, pressed "Approve" |
| 3 | 15:45:33 | wallet | Google account chooser ("Zyton Shop") |
| – | 15:45:37 | (wait) | "Reconstructing your key…" |
| – | 15:45:40.7–15:45:44 | (transient) | sign-in dialog flashes on the operator page and closes without input |
| – | 15:45:44–46 | (result) | node shows "Approved" (≈ 19 s after pressing Approve) |
| 4 | 16:09:36 | page | pressed "Publish Changes" |
| 5 | 16:09:37 | page | Publish dialog (six steps, "This will: let Fabric Formation contribute", "67 values" toggle opened and closed, permanence note; no checkbox): pressed "Publish" (≈16:09:44) |
| 6 | 16:09:46 | wallet | sign-in dialog during "Working…": chose Google |
| 7 | 16:10:00 | wallet | Google account chooser ("Zyton Shop"), chosen 16:10:02 |
| – | 16:10:09–13 | (wait) | "Confirm your Google account" → tick; "Confirming the parts you provide" ✓, "Confirming it's you" ✓ |
| – | 16:10:18 | (wait) | "Recording on the public ledger — 1 record still confirming…" |
| 8 | 16:11:27 | page | "Published and sealed. Anyone can now check this passport against the public ledger." — all six steps ✓; pressed "Done" (16:11:28) |
**Count: 8 interactions (5 pages, 3 wallet dialogs); Design B operator: 3 pages.**
Publish timing: "Publish" ≈16:09:44 → key confirmed 16:10:13 (≈ 31 s, of which the Google
sign-in most) → ledger recording 16:10:18 → sealed 16:11:27 (≈ 69 s waiting for chain
confirmation) — ≈ 1 min 45 s from pressing Publish to sealed.

## Findings (for Section 7.7)
Checked against the code the live origin serves: the web3.trustdpp.co bundle chunk
`web3auth-BoT_ZAaK.js` (fetched 2026-10-06) contains the current `frontend_dpp/src/lib/wallet/web3auth.ts`
behaviour (logout with cleanup after every ceremony, one retry, MFA fallback); no frontend change since v1.1.27.
1. One key-infrastructure sign-in per ceremony, as designed: every ceremony opens a session and ends with
   `logout({cleanup:true})`, and sessions are held in memory only. Observed: supplier 2 sign-ins (onboarding,
   signing), operator 2 (approval, publish; the publish runs as ONE session for all its signatures). The
   signing re-login therefore costs the supplier a second e-mail code; it is the price of not persisting a
   session, not a defect.
2. After each ceremony's logout a sign-in dialog flashes for 3–8 s and closes by itself (15:43:11–19,
   15:45:10.7–14.2, operator 15:45:40.7–44.0). No input; not counted. A cosmetic SDK artifact.
3. One invalid one-time code at signing (15:44:46), recovered by reading the mailbox again (≈ 30 s).
4. MFA (authenticator app, marked required) is enforced at enrolment; the signing sign-in asked only for the
   e-mail code (the device share stood in for the second factor).
5. Browser interruptions not caused by the application: a detour into Chrome's password manager (B),
   Chrome's local-network permission prompt (A, 15:43:39).
6. Protocol deviations: one mailbox for both designs (the protocol asked for a fresh address per design), which
   led to opening the wrong invitation once; Design A fields were prefilled from an earlier seed ("needs
   re-confirming"), Design B fields were typed — field entry is not part of the count, but durations differ on that point.
