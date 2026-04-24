# Configure Alerts

NetWatchAI supports three **free** channels out of the box. Configure them from the
**Settings** tab in the dashboard.

## Discord

1. In your Discord server, go to **Server Settings → Integrations → Webhooks**.
2. Click **New Webhook**, pick a channel, and copy the webhook URL.
3. In NetWatchAI, paste the URL into **Settings → Alert Channels → Discord webhook**.
4. Click **Send test alert** — you should see a message in the Discord channel within a second.

## Slack

1. Visit [api.slack.com/messaging/webhooks](https://api.slack.com/messaging/webhooks).
2. Create a new app, enable **Incoming Webhooks**, authorise it on your workspace, and copy the URL.
3. Paste into **Settings → Alert Channels → Slack webhook**.
4. Click **Send test alert**.

## Email (free via Gmail SMTP)

1. Enable 2-factor auth on your Google account.
2. Generate an **App Password** at [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords).
3. Fill in **Settings → Alert Channels**:
   - **SMTP host:** `smtp.gmail.com`
   - **SMTP port:** `587`
   - **SMTP username:** `yourname@gmail.com`
   - **SMTP password:** the 16-character App Password (not your Google password)
   - **Send alerts to:** the recipient address
4. Click **Send test alert**.

Gmail's free tier allows 500 outbound emails per day — more than enough for home and SMB use.

## Minimum severity

Pick the severity at which NetWatchAI starts paging you:

- **Low:** every anomaly. Useful during initial tuning; noisy in production.
- **Medium:** anomaly rate ≥ 5%.
- **High:** anomaly rate ≥ 15%. **Recommended default.**
- **Critical:** anomaly rate ≥ 30%. "Active attack" territory.

## Reducing noise

- Use **Allowlist** for internal scanners, load balancers, and monitoring tools that look
  like attackers to the model.
- Click **False positive** on any alert you want to retract. The feedback is logged for
  future ML improvements.
- The dedup window (default 5 minutes) coalesces repeated events from the same source
  into a single alert. Tune it under **Settings** if needed.
