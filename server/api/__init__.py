"""
GIAM-SAT API Route Modules.
Each module registers its routes on the Flask app.
"""
from . import api_common
from . import api_auth
from . import api_machines
from . import api_events
from . import api_threats
from . import api_rules
from . import api_groups
from . import api_fim_baseline
from . import api_agent_update
from . import api_attack_overview
from . import api_ai
from . import api_reports
from . import api_agentless
from . import api_email
from . import api_cluster
from . import api_panorama
from . import api_messages
from . import api_hunt
from . import api_cleanup
from . import api_incident
from . import api_suppression
from . import api_policies
from . import api_mitre
from . import api_response
from . import api_agent_commands
from . import api_health
from . import api_dashboard
from . import api_custom_dashboard
from . import api_alert_approval
from . import api_assets
from . import api_netflow

def register_all_routes(app, core):
    """Register all API route modules on the Flask app."""
    api_common.register(app, core)
    api_auth.register(app, core)
    api_machines.register(app, core)
    api_events.register(app, core)
    api_threats.register(app, core)
    api_rules.register(app, core)
    api_groups.register(app, core)
    api_fim_baseline.register(app, core)
    api_agent_update.register(app, core)
    api_attack_overview.register(app, core)
    api_ai.register(app, core)
    api_reports.register(app, core)
    api_agentless.register(app, core)
    api_email.register(app, core)
    api_cluster.register(app, core)
    api_panorama.register(app, core)
    api_messages.register(app, core)
    api_hunt.register(app, core)
    api_cleanup.register(app, core)
    api_incident.register(app, core)
    api_suppression.register(app, core)
    api_policies.register_routes(app, core)
    api_mitre.register_routes(app, core)
    api_response.register(app, core)
    api_agent_commands.register(app, core)
    api_health.register(app, core)
    api_dashboard.register(app, core)
    api_custom_dashboard.register(app, core)
    api_alert_approval.register(app, core)
    api_assets.init_assets_api(app, core.db)
    api_netflow.register(app, core)
