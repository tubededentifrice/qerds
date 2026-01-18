"""
QERDS Mocks Server
A simple Flask application to serve UI mockups with sample data
"""

from datetime import datetime, timedelta
from flask import Flask, render_template, request
import uuid

app = Flask(__name__)

# Configuration
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Mock data generators
def generate_delivery_id():
    return str(uuid.uuid4())

def format_date(dt):
    return dt.strftime('%d/%m/%Y à %H:%M')

# Sample mock data
MOCK_USER_SENDER = {
    'name': 'Marie Dupont',
    'email': 'marie.dupont@example.com',
    'initials': 'MD',
    'role': 'sender'
}

MOCK_USER_ADMIN = {
    'name': 'Admin Système',
    'email': 'admin@qerds.example.com',
    'initials': 'AS',
    'role': 'admin'
}

MOCK_STATS_SENDER = {
    'this_month': 24,
    'pending': 5,
    'accepted': 18,
    'refused_or_expired': 1,
    'drafts': 2
}

MOCK_STATS_ADMIN = {
    'today': 47,
    'month': 1248,
    'pending': 156,
    'acceptance_rate': '87%'
}

def get_mock_deliveries():
    now = datetime.now()
    return [
        {
            'id': 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
            'recipient_email': 'jean.martin@example.com',
            'subject': 'Résiliation de contrat',
            'status': 'accepted',
            'created_at': (now - timedelta(days=2)).isoformat(),
            'created_at_formatted': format_date(now - timedelta(days=2)),
            'updated_at': (now - timedelta(days=1)).isoformat(),
        },
        {
            'id': 'b2c3d4e5-f6a7-8901-bcde-f12345678901',
            'recipient_email': 'pierre.durand@example.com',
            'subject': 'Mise en demeure',
            'status': 'notified',
            'created_at': (now - timedelta(days=1)).isoformat(),
            'created_at_formatted': format_date(now - timedelta(days=1)),
            'updated_at': now.isoformat(),
        },
        {
            'id': 'c3d4e5f6-a7b8-9012-cdef-123456789012',
            'recipient_email': 'sophie.bernard@example.com',
            'subject': 'Convocation assemblée générale',
            'status': 'available',
            'created_at': (now - timedelta(hours=6)).isoformat(),
            'created_at_formatted': format_date(now - timedelta(hours=6)),
            'updated_at': now.isoformat(),
        },
        {
            'id': 'd4e5f6a7-b8c9-0123-defa-234567890123',
            'recipient_email': 'lucas.petit@example.com',
            'subject': 'Notification de sinistre',
            'status': 'draft',
            'created_at': now.isoformat(),
            'created_at_formatted': format_date(now),
            'updated_at': now.isoformat(),
        },
    ]

def get_mock_pickup_delivery():
    now = datetime.now()
    return {
        'id': 'e5f6a7b8-c9d0-1234-efab-345678901234',
        'subject': 'Notification importante',
        'status': 'available',
        'deposited_at': (now - timedelta(days=3)).isoformat(),
        'deposited_at_formatted': format_date(now - timedelta(days=3)),
        'expires_at': (now + timedelta(days=12)).isoformat(),
        'expires_at_formatted': format_date(now + timedelta(days=12)),
        'content_size': '1.2 Mo',
        'content_filename': 'notification.pdf',
        # Post-acceptance data (only shown after accept)
        'sender_name': 'Société ABC',
        'sender_email': 'contact@societe-abc.fr',
        'accepted_at_formatted': format_date(now),
        'proof_id': 'PRF-2024-ABCD-1234-5678',
    }

def get_mock_recent_events():
    now = datetime.now()
    return [
        {
            'timestamp': format_date(now - timedelta(minutes=5)),
            'type': 'accepted',
            'delivery_id': 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
            'details': 'Preuve d\'acceptation générée',
        },
        {
            'timestamp': format_date(now - timedelta(minutes=15)),
            'type': 'notified',
            'delivery_id': 'b2c3d4e5-f6a7-8901-bcde-f12345678901',
            'details': 'Email de notification envoyé',
        },
        {
            'timestamp': format_date(now - timedelta(minutes=30)),
            'type': 'deposited',
            'delivery_id': 'c3d4e5f6-a7b8-9012-cdef-123456789012',
            'details': 'Nouveau dépôt par Marie Dupont',
        },
        {
            'timestamp': format_date(now - timedelta(hours=1)),
            'type': 'refused',
            'delivery_id': 'x1y2z3w4-5678-90ab-cdef-ghijklmnopqr',
            'details': 'Refusé par le destinataire',
        },
        {
            'timestamp': format_date(now - timedelta(hours=2)),
            'type': 'expired',
            'delivery_id': 'p9q8r7s6-5432-10fe-dcba-zyxwvutsrqpo',
            'details': 'Délai de 15 jours expiré',
        },
    ]

def get_mock_verification_result(valid=True):
    now = datetime.now()
    if valid:
        return {
            'valid': True,
            'proof_type': 'Preuve d\'Acceptation',
            'issued_at': format_date(now - timedelta(days=1)),
            'delivery_id': 'e5f6a7b8-c9d0-1234-efab-345678901234',
            'sender_name': 'Société ABC',
            'recipient_name': 'Jean Martin',
            'show_parties': True,
            'signature_algorithm': 'ECDSA-P384-SHA384',
            'tsa_name': 'Chronosign (Qualifié eIDAS)',
            'document_hash': 'sha384:a7f8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8',
        }
    else:
        return {
            'valid': False,
            'error': 'Identifiant ou jeton de vérification invalide',
        }


# Context processor for common variables
@app.context_processor
def inject_common():
    return {
        'current_year': datetime.now().year,
        'qualification_mode': request.args.get('mode', 'dev'),  # 'qualified' or 'dev'
    }


# Routes
@app.route('/')
def index():
    return render_template('login.html')


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/sender/dashboard')
def sender_dashboard():
    return render_template(
        'sender/dashboard.html',
        user=MOCK_USER_SENDER,
        active_page='dashboard',
        stats=MOCK_STATS_SENDER,
        deliveries=get_mock_deliveries(),
    )


@app.route('/sender/new')
def sender_new():
    return render_template(
        'sender/new.html',
        user=MOCK_USER_SENDER,
        active_page='new',
    )


@app.route('/recipient/pickup')
@app.route('/recipient/pickup/<token>')
def recipient_pickup(token=None):
    # Simulate authenticated vs unauthenticated state
    authenticated = request.args.get('auth') == '1'
    return render_template(
        'recipient/pickup.html',
        user=MOCK_USER_SENDER if authenticated else None,
        delivery=get_mock_pickup_delivery(),
    )


@app.route('/recipient/accepted')
@app.route('/recipient/accepted/<delivery_id>')
def recipient_accepted(delivery_id=None):
    return render_template(
        'recipient/accepted.html',
        user=MOCK_USER_SENDER,
        delivery=get_mock_pickup_delivery(),
    )


@app.route('/admin/dashboard')
def admin_dashboard():
    return render_template(
        'admin/dashboard.html',
        user=MOCK_USER_ADMIN,
        active_page='dashboard',
        stats=MOCK_STATS_ADMIN,
        recent_events=get_mock_recent_events(),
    )


@app.route('/verify')
def verify():
    proof_id = request.args.get('id')
    token = request.args.get('token')

    result = None
    if proof_id and token:
        # Simulate verification - show valid result for demo
        result = get_mock_verification_result(valid=True)

    return render_template(
        'verify.html',
        proof_id=proof_id,
        token=token,
        result=result,
    )


# Error handlers
@app.errorhandler(404)
def not_found(e):
    return render_template('base.html', error='Page non trouvée'), 404


@app.errorhandler(500)
def server_error(e):
    return render_template('base.html', error='Erreur serveur'), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
