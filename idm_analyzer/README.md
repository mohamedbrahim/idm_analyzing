# IDM Permission Analyzer

Interactive web application to analyze FreeIPA/IDM user permissions, trace permission sources, and compare users.

## Features

- **Analyze User Permissions**: Visualize complete permission tree with groups, HBAC rules, and sudo rules
- **Interactive Graph**: D3.js-powered graph with zoom, pan, and click-to-inspect nodes
- **Trace Permission Source**: Find exactly where a user's sudo permission on a specific VM comes from
- **Compare Users**: Side-by-side comparison showing differences and common permissions
- **Browse Rules**: View all HBAC rules, sudo rules, and groups in your environment
- **Nested Group Support**: Automatically discovers and displays nested group memberships

## Screenshots

```
┌─────────────────────────────────────────────────────────────┐
│  IDM Analyzer          │  Analyze User Permissions          │
├─────────────────────────┤                                    │
│  ▶ Analyze User        │  ┌─────────────────────────────┐   │
│    Compare Users       │  │ [Search users...]  [Analyze]│   │
│    Trace Permission    │  └─────────────────────────────┘   │
│    Browse Rules        │                                    │
│                        │  ┌─────┐ ┌─────┐ ┌─────┐          │
│                        │  │ 12  │ │  5  │ │  3  │          │
│  ● Connected           │  │Groups│ │HBAC │ │Sudo │          │
└─────────────────────────┴──┴─────┴─┴─────┴─┴─────┴──────────┘
```

## Installation

### Prerequisites

- Python 3.8+
- Access to a FreeIPA/IDM server
- Valid credentials (password or Kerberos ticket)

### Setup

```bash
# Clone or copy the project
cd idm_analyzer

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Start the Application

```bash
# With password authentication
python app.py -s ipa.example.com -l admin

# With Kerberos authentication (requires valid ticket)
kinit admin
python app.py -s ipa.example.com -k

# Custom port and host
python app.py -s ipa.example.com -l admin --port 8080 --host 0.0.0.0
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-s, --server` | FreeIPA server hostname (required) |
| `-l, --login` | Username for authentication |
| `-p, --password` | Password (will prompt if not provided) |
| `-k, --kerberos` | Use Kerberos authentication |
| `--port` | Web server port (default: 5000) |
| `--host` | Web server host (default: 127.0.0.1) |
| `--verify-ssl` | Verify SSL certificates |
| `--debug` | Enable debug mode |

### Access the Web Interface

Open your browser and navigate to: `http://localhost:5000`

## Features in Detail

### 1. Analyze User

Select a user to see their complete permission analysis:

- **User Information**: Basic user details
- **Statistics**: Count of groups, HBAC rules, sudo rules
- **Permission Graph**: Interactive visualization showing:
  - Direct group memberships
  - Nested group relationships
  - HBAC rules (with connection path)
  - Sudo rules (with connection path)
- **Detail Tables**: Sortable tables for groups, HBAC, and sudo rules

### 2. Compare Users

Compare two users side-by-side to see:

- Groups unique to each user
- Common groups
- HBAC rules unique to each user
- Common HBAC rules
- Sudo rules unique to each user
- Common sudo rules

### 3. Trace Permission

Answer the question: "Why does user X have sudo on server Y?"

- Enter username and optionally filter by hostname
- See all matching sudo rules
- View the complete path from user to rule (user → group → parent group → rule)
- See what commands are allowed and as which user

### 4. Browse Rules

View all rules in your environment:

- HBAC Rules (with enabled/disabled status)
- Sudo Rules (with enabled/disabled status)
- Groups (with descriptions)

## API Endpoints

The application exposes REST API endpoints:

| Endpoint | Description |
|----------|-------------|
| `GET /api/users` | List all users |
| `GET /api/user/<uid>` | Get user details |
| `GET /api/user/<uid>/analyze` | Full permission analysis |
| `GET /api/user/<uid>/graph` | Graph visualization data |
| `GET /api/user/<uid>/trace-sudo?host=X` | Trace sudo permissions |
| `GET /api/compare?user1=X&user2=Y` | Compare two users |
| `GET /api/groups` | List all groups |
| `GET /api/hosts` | List all hosts |
| `GET /api/hbac-rules` | List all HBAC rules |
| `GET /api/sudo-rules` | List all sudo rules |

## Project Structure

```
idm_analyzer/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── static/
│   ├── css/
│   │   └── style.css     # Application styles
│   └── js/
│       └── app.js        # Frontend JavaScript
└── templates/
    └── index.html        # Main HTML template
```

## Troubleshooting

### Connection Issues

```bash
# Test connectivity to IPA server
curl -k https://ipa.example.com/ipa/json

# Check Kerberos ticket
klist
```

### SSL Certificate Errors

If using self-signed certificates, the app disables SSL verification by default. For production, use `--verify-ssl` with proper certificates.

### Permission Denied

Ensure the user you're authenticating with has permission to read user, group, HBAC, and sudo rule information.

## Security Considerations

- The application caches IDM data in memory for performance
- Run on localhost only unless properly secured
- Use HTTPS in production with a reverse proxy
- Consider network segmentation for the IDM server

## Contributing

Suggestions for improvements:

1. **Add Role Support**: Extend to show FreeIPA role-based access
2. **Host Analysis**: Analyze which users can access a specific host
3. **Export Options**: Export reports as PDF/HTML
4. **Audit Trail**: Track permission changes over time
5. **LDAP Support**: Direct LDAP queries for non-IPA environments

## License

MIT License - Feel free to use and modify.
