# QERDS UI Mocks

Interactive UI mockups for the QERDS (Qualified Electronic Registered Delivery Service) platform.

## Quick Start

```bash
# From the repository root:
docker compose up mocks

# Access at: http://localhost:5000
```

## Available Pages

| URL | Description |
|-----|-------------|
| `/` | Login page |
| `/login` | Login page (FranceConnect+ style) |
| `/sender/dashboard` | Sender dashboard with delivery list |
| `/sender/new` | Create new delivery form |
| `/recipient/pickup` | Recipient pickup portal (unauthenticated) |
| `/recipient/pickup?auth=1` | Recipient pickup portal (authenticated - shows accept/refuse) |
| `/recipient/accepted` | Post-acceptance view with content download |
| `/admin/dashboard` | Admin dashboard with system status |
| `/verify` | Public proof verification portal |
| `/verify?id=PRF-123&token=ABC` | Verification with result |

## URL Parameters

- `?mode=qualified` - Show qualified service indicators
- `?mode=dev` - Show development mode warnings (default)

## Design System

The UI follows a French government-inspired design language:

- **Primary Color**: French government blue (`#000091`)
- **Accent**: French red (`#E1000F`) for critical actions
- **Typography**: Source Sans 3 (body), Spectral (headings)
- **Layout**: Clean, structured, generous whitespace

### Key UI Elements

1. **Qualification Indicator**: Banner showing qualified vs. dev mode status
2. **Sender Identity Protection**: Redacted sender info before recipient accept/refuse (CPCE compliance)
3. **Status Badges**: Color-coded delivery status indicators
4. **Proof Downloads**: Clear access to legal evidence documents

## Installing Fonts (Optional)

For the best visual experience, download and install the fonts:

1. Download [Source Sans 3](https://fonts.google.com/specimen/Source+Sans+3)
2. Download [Spectral](https://fonts.google.com/specimen/Spectral)
3. Convert to WOFF2 format
4. Place in `static/fonts/`:
   - `SourceSans3-Light.woff2`
   - `SourceSans3-Regular.woff2`
   - `SourceSans3-Medium.woff2`
   - `SourceSans3-SemiBold.woff2`
   - `SourceSans3-Bold.woff2`
   - `SourceSans3-Italic.woff2`
   - `Spectral-Medium.woff2`
   - `Spectral-SemiBold.woff2`

Without custom fonts, the system falls back to similar system fonts.

## Development

### Local Development (without Docker)

```bash
cd mocks
pip install -r requirements.txt
python app.py
```

### File Structure

```
mocks/
├── app.py                 # Flask application with mock data
├── requirements.txt       # Python dependencies
├── templates/
│   ├── base.html          # Base Jinja2 template
│   ├── login.html         # Login page
│   ├── verify.html        # Verification portal
│   ├── partials/          # Reusable components
│   │   ├── dev_banner.html
│   │   ├── status_badge.html
│   │   └── delivery_card.html
│   ├── sender/
│   │   ├── dashboard.html
│   │   └── new.html
│   ├── recipient/
│   │   ├── pickup.html
│   │   └── accepted.html
│   └── admin/
│       └── dashboard.html
└── static/
    ├── css/
    │   ├── main.css       # Complete design system
    │   └── fonts.css      # Font definitions
    ├── js/
    │   └── main.js        # Progressive enhancement
    └── fonts/             # Self-hosted fonts (optional)
```

## Compliance Notes

These mocks demonstrate compliance with:

- **eIDAS Article 44**: Qualified electronic registered delivery
- **CPCE (France)**: Sender identity protection before accept/refuse
- **REQ-F03**: Recipient cannot see sender identity until decision is made
- **REQ-G02**: Clear labeling of non-qualified/dev mode
